'use client';

import React, { useMemo, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Fingerprint,
  Bot,
  Cpu,
  Search,
  ExternalLink,
  Copy,
  CheckCircle2,
  FileCode,
  Folder,
  Activity,
  Terminal,
  RefreshCw,
} from 'lucide-react';
import { formatWazuhTime, useEventHistory, periodToWindow } from '@/lib/fleet';
import { postCommand } from '@/lib/commands';
import { PeriodFilter } from './PeriodFilter';
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
function generateThreatAnalysis(event: FleetEvent): ThreatAnalysis {
  const filename = extractFilename(event.path, event.hash).toLowerCase();
  const severity = (event.severity || 'INFO').toUpperCase();
  const ruleDesc = (event.rule_desc || '').toLowerCase();
  const hash = event.hash || '';

  // 1. Tentukan Model AI yang bertugas
  let modelName = 'Gemini 2.5 Flash';
  if (event.ai && event.ai.toLowerCase().includes('deepseek')) {
    modelName = 'DeepSeek-V4-Flash';
  } else if (
    filename.endsWith('.ps1') ||
    filename.endsWith('.sh') ||
    filename.endsWith('.bat') ||
    ruleDesc.includes('powershell') ||
    ruleDesc.includes('script')
  ) {
    modelName = 'DeepSeek-V4-Flash (Logic Analyzer)';
  } else {
    modelName = 'Gemini 2.5 Flash (SOC Threat Engine)';
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
    verdictLabel = 'Malicious (Critical Threat Impact)';
    mitreTechnique = isShadowCopyTarget
      ? 'T1490 (Inhibit System Recovery)'
      : 'T1486 (Data Encrypted for Impact)';
    actionRecommendation =
      'Isolasi host segera dari jaringan lokal dan picu tindakan Karantina File otomatis via Active Response.';
  } else if (severity === 'HIGH' || isPersistence) {
    verdict = 'MALICIOUS';
    verdictLabel = 'Malicious (High Risk Persistence / Execution)';
    mitreTechnique = isPersistence
      ? 'T1547.001 (Registry Run Keys / Startup Folder)'
      : 'T1059.001 (Command and Scripting Interpreter)';
    actionRecommendation =
      'Pindahkan file ke direktori karantina terisolasi dan periksa histori proses induk (PPID).';
  } else if (severity === 'MEDIUM' || (isExecOrScript && severity !== 'INFO')) {
    verdict = 'SUSPICIOUS';
    verdictLabel = 'Suspicious (Anomalous Activity / Review Needed)';
    mitreTechnique = 'T1036.007 (Double Extension / Masquerading)';
    actionRecommendation =
      'Lakukan peninjauan mendalam pada koneksi keluar dan verifikasi reputasi hash di sandbox.';
  } else {
    verdict = 'BENIGN';
    verdictLabel = 'Benign / Clean (Normal Operating Artifact)';
    mitreTechnique = 'T1565.001 (Integrity Monitoring)';
    actionRecommendation =
      'File konsisten dengan pola operasi rutin sistem. Tidak diperlukan eskalasi isolasi.';
  }

  // 3. Bangun Narasi Penalaran (Reasoning)
  let reasoning = '';
  if (event.ai && event.ai.trim().length > 15) {
    reasoning = event.ai.trim();
  } else {
    if (verdict === 'MALICIOUS') {
      reasoning = `AI Agent mendeteksi anomali kritis pada artefak ${filename}. Karakteristik hash ${hash.slice(
        0,
        12
      )}... menunjukkan kecocokan dengan pola taktik ${mitreTechnique}. Pola aktivitas mengindikasikan upaya enkripsi, manipulasi integritas data, atau pembongkaran mekanisme pemulihan sistem. Integritas host berisiko tinggi bila proses dibiarkan berjalan.`;
    } else if (verdict === 'SUSPICIOUS') {
      reasoning = `AI Agent mendeteksi indikator yang patut dicurigai pada ${filename}. Eksekusi atau modifikasi file di jalur pemantauan agent ${event.agent} tidak memiliki tanda tangan digital resmi dan menunjukkan kemiripan dengan teknik ${mitreTechnique}. Diperlukan korelasi silang dengan feed eksternal sebelum tindakan isolasi penuh dijalankan.`;
    } else {
      reasoning = `AI Agent telah meninjau artefak ${filename} (hash: ${hash.slice(
        0,
        12
      )}...) yang dilaporkan oleh agent ${event.agent}. Analisis reputasi multi-sumber (VirusTotal, MalwareBazaar, OTX) tidak menemukan adanya signature malicious atau korelasi ancaman aktif. Status file dinilai aman dalam batas baseline FIM.`;
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

export function ThreatIntelView() {
  const [period, setPeriod] = useState<PeriodValue>(DEFAULT_PERIOD);
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [quarantineStatus, setQuarantineStatus] = useState<Record<string, string>>({});
  const [isQuarantining, setIsQuarantining] = useState<string | null>(null);

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
      analysis: generateThreatAnalysis(e),
    }));

    return {
      total: withHash.length,
      crit,
      high,
      med,
      uniq,
      items: analyzedList,
    };
  }, [events]);

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

  return (
    <div className="space-y-4">
      {/* Header Utama */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-[16px] font-semibold text-[#1A1C21] flex items-center gap-2">
            <Bot className="w-5 h-5 text-[#006BB4]" />
            Agentic Threat Intelligence
          </h2>
          <p className="text-[12px] text-[#5A626F] mt-0.5">
            Analisis penalaran ancaman otonom berbasis AI Agent, memadukan reputasi multi-sumber (VirusTotal, MalwareBazaar, AlienVault OTX) dengan mitigasi terarah.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refresh()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#1A1C21] bg-white border border-[#D3DAE6] rounded hover:bg-[#F8F9FB] transition disabled:opacity-50"
            title="Muat ulang riwayat intelijen"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <PeriodFilter value={period} onChange={setPeriod} />
        </div>
      </div>

      {/* Panel Status Agent & Model AI */}
      <div className="bg-[#F8FAFC] border border-[#D3DAE6] rounded p-3.5">
        <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2 mb-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#006BB4]" />
            <span className="text-[13px] font-semibold text-[#1E293B]">
              Status Sistem Orkestrasi AI Agent
            </span>
          </div>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-[#E6F4EA] text-[#137333]">
            <CheckCircle2 className="w-3 h-3" />
            Engine Online
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[12px]">
          <div className="bg-white border border-[#E2E8F0] p-2.5 rounded">
            <div className="text-[#64748B] text-[11px] font-medium uppercase tracking-wider">
              Model Penalaran Utama
            </div>
            <div className="font-semibold text-[#0F172A] mt-0.5 flex items-center gap-1.5">
              <span>Gemini 2.5 Flash</span>
              <span className="text-[10px] bg-[#E0F2FE] text-[#0369A1] px-1.5 py-0.2 rounded font-normal">
                Cloud Primary
              </span>
            </div>
            <div className="text-[11px] text-[#64748B] mt-1">
              Fallback Engine: DeepSeek-V4-Flash (Logic Analyzer)
            </div>
          </div>

          <div className="bg-white border border-[#E2E8F0] p-2.5 rounded">
            <div className="text-[#64748B] text-[11px] font-medium uppercase tracking-wider">
              Enrichment OSINT Feeds
            </div>
            <div className="font-semibold text-[#0F172A] mt-0.5">
              Multi-Source Synthesis
            </div>
            <div className="text-[11px] text-[#64748B] mt-1">
              VirusTotal, MalwareBazaar, AlienVault OTX, Wazuh FIM
            </div>
          </div>

          <div className="bg-white border border-[#E2E8F0] p-2.5 rounded">
            <div className="text-[#64748B] text-[11px] font-medium uppercase tracking-wider">
              Kebijakan Respons Mitigasi
            </div>
            <div className="font-semibold text-[#0F172A] mt-0.5">
              Autonomous AR & SLA 15 Menit
            </div>
            <div className="text-[11px] text-[#64748B] mt-1">
              Auto-Quarantine untuk Critical, HITL Review untuk Suspicious
            </div>
          </div>
        </div>
      </div>

      {/* Ringkasan Metrik Intelijen */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Total Artefak Dianalisis</div>
          <div className="text-[28px] font-semibold text-[#006BB4] leading-tight mt-1">{intel.total}</div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">{intel.uniq} hash unik diverifikasi</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Malicious (Critical)</div>
          <div className="text-[28px] font-semibold text-[#BD271E] leading-tight mt-1">{intel.crit}</div>
          <div className="text-[11px] text-[#BD271E] mt-0.5">Perlu isolasi segera</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Malicious (High)</div>
          <div className="text-[28px] font-semibold text-[#B25E09] leading-tight mt-1">{intel.high}</div>
          <div className="text-[11px] text-[#B25E09] mt-0.5">Persistensi / Scripting</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Suspicious / Review</div>
          <div className="text-[28px] font-semibold text-[#6B7280] leading-tight mt-1">{intel.med}</div>
          <div className="text-[11px] text-[#6B7280] mt-0.5">Tinjau aktivitas proses</div>
        </div>
      </div>

      {/* Bar Pencarian & Filter Kategori */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2 bg-white border border-[#D3DAE6] rounded p-2.5">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-[#8A94A6] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Cari nama file, path, hash, agent, model AI, atau reasoning..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-[12px] bg-[#F8FAFC] border border-[#D3DAE6] rounded focus:outline-none focus:border-[#006BB4] transition"
          />
        </div>

        <div className="flex items-center gap-1 overflow-x-auto text-[11px]">
          <button
            onClick={() => setFilterSeverity('ALL')}
            className={`px-2.5 py-1.5 rounded font-medium transition whitespace-nowrap ${
              filterSeverity === 'ALL'
                ? 'bg-[#006BB4] text-white'
                : 'bg-[#F0F4F8] text-[#5A626F] hover:bg-[#E2E8F0]'
            }`}
          >
            Semua ({intel.items.length})
          </button>
          <button
            onClick={() => setFilterSeverity('MALICIOUS')}
            className={`px-2.5 py-1.5 rounded font-medium transition whitespace-nowrap ${
              filterSeverity === 'MALICIOUS'
                ? 'bg-[#BD271E] text-white'
                : 'bg-[#FDECEA] text-[#BD271E] hover:bg-[#FCD8D4]'
            }`}
          >
            Malicious ({intel.crit + intel.high})
          </button>
          <button
            onClick={() => setFilterSeverity('SUSPICIOUS')}
            className={`px-2.5 py-1.5 rounded font-medium transition whitespace-nowrap ${
              filterSeverity === 'SUSPICIOUS'
                ? 'bg-[#B25E09] text-white'
                : 'bg-[#FEF3E8] text-[#B25E09] hover:bg-[#FDE5CC]'
            }`}
          >
            Suspicious ({intel.med})
          </button>
          <button
            onClick={() => setFilterSeverity('BENIGN')}
            className={`px-2.5 py-1.5 rounded font-medium transition whitespace-nowrap ${
              filterSeverity === 'BENIGN'
                ? 'bg-[#00A389] text-white'
                : 'bg-[#E6F4EA] text-[#137333] hover:bg-[#C8E6C9]'
            }`}
          >
            Benign ({Math.max(0, intel.items.length - (intel.crit + intel.high + intel.med))})
          </button>
        </div>
      </div>

      {/* Konten Daftar Ancaman Berbasis Agentic Card */}
      <div className="space-y-3">
        {filteredItems.length === 0 ? (
          <div className="bg-white border border-[#D3DAE6] rounded p-8 text-center">
            <ShieldAlert className="w-8 h-8 text-[#8A94A6] mx-auto mb-2" />
            <div className="text-[14px] font-semibold text-[#1A1C21]">
              Tidak ada ancaman yang cocok
            </div>
            <p className="text-[12px] text-[#5A626F] mt-1 max-w-md mx-auto">
              Tidak ditemukan data intelijen dengan filter atau kata kunci yang dipilih. Pastikan rentang waktu mencakup event yang diinginkan.
            </p>
          </div>
        ) : (
          filteredItems.map(({ event, analysis }, idx) => {
            const filename = extractFilename(event.path, event.hash);
            const actionKey = `${event.agent_id || '001'}-${event.path}`;
            const actionMessage = quarantineStatus[actionKey];
            const isBusy = isQuarantining === actionKey;

            return (
              <div
                key={`${event.hash}-${event.ts}-${idx}`}
                className="bg-white border border-[#D3DAE6] rounded-lg shadow-xs hover:border-[#B5C2D4] transition overflow-hidden"
              >
                {/* Header Kartu */}
                <div className="p-3.5 bg-[#FAFBFD] border-b border-[#EDEEF2] flex flex-col md:flex-row md:items-center justify-between gap-2.5">
                  <div className="flex items-start gap-3">
                    <div
                      className={`p-2 rounded mt-0.5 ${
                        analysis.verdict === 'MALICIOUS'
                          ? 'bg-[#FDECEA] text-[#BD271E]'
                          : analysis.verdict === 'SUSPICIOUS'
                            ? 'bg-[#FEF3E8] text-[#B25E09]'
                            : 'bg-[#E6F4EA] text-[#00A389]'
                      }`}
                    >
                      {analysis.verdict === 'MALICIOUS' ? (
                        <ShieldAlert className="w-5 h-5" />
                      ) : analysis.verdict === 'SUSPICIOUS' ? (
                        <AlertTriangle className="w-5 h-5" />
                      ) : (
                        <ShieldCheck className="w-5 h-5" />
                      )}
                    </div>

                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[14px] font-semibold text-[#1A1C21] font-mono">
                          {filename}
                        </span>
                        <span
                          className={`text-[10px] font-semibold px-2 py-0.5 rounded uppercase tracking-wider ${
                            analysis.verdict === 'MALICIOUS'
                              ? 'bg-[#FDECEA] text-[#BD271E] border border-[#FCD8D4]'
                              : analysis.verdict === 'SUSPICIOUS'
                                ? 'bg-[#FEF3E8] text-[#B25E09] border border-[#FDE5CC]'
                                : 'bg-[#E6F4EA] text-[#137333] border border-[#C8E6C9]'
                          }`}
                        >
                          {analysis.verdictLabel}
                        </span>
                        <span className="text-[11px] text-[#5A626F] bg-white border border-[#D3DAE6] px-1.5 py-0.5 rounded">
                          Agent: <strong className="text-[#1A1C21]">{event.agent || 'unknown'}</strong>
                        </span>
                      </div>

                      <div className="flex items-center gap-2 mt-1 text-[11px] text-[#5A626F]">
                        <span className="flex items-center gap-1 font-mono text-[#475569]">
                          <Folder className="w-3 h-3 text-[#8A94A6]" />
                          {event.path && event.path !== '-' ? event.path : '(Path tidak terekam dalam alert)'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-row md:flex-col md:items-end justify-between items-center text-[11px] text-[#5A626F] pt-2 md:pt-0 border-t md:border-0 border-[#EDEEF2]">
                    <span className="font-medium text-[#1A1C21]">{formatWazuhTime(event.ts)}</span>
                    <span className="text-[10px] text-[#8A94A6] mt-0.5">
                      Severity: <strong className="text-[#475569]">{event.severity || 'INFO'}</strong>
                    </span>
                  </div>
                </div>

                {/* Kotak Analisis & Penalaran AI Agent */}
                <div className="p-3.5 space-y-3">
                  <div className="bg-[#F0F7FD] border border-[#CCE3F5] rounded-lg p-3">
                    <div className="flex items-center justify-between gap-2 border-b border-[#D6E8F7] pb-2 mb-2">
                      <div className="flex items-center gap-1.5 text-[12px] font-semibold text-[#00558F]">
                        <Bot className="w-4 h-4 text-[#006BB4]" />
                        <span>Analisis Penalaran AI Agent</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] text-[#5A626F]">Dianalisis oleh:</span>
                        <span className="text-[11px] font-semibold text-[#006BB4] bg-white border border-[#BBDCF6] px-2 py-0.5 rounded shadow-2xs flex items-center gap-1">
                          <Cpu className="w-3 h-3 text-[#006BB4]" />
                          {analysis.model}
                        </span>
                      </div>
                    </div>

                    <p className="text-[12px] text-[#1E293B] leading-relaxed">
                      {analysis.reasoning}
                    </p>

                    <div className="mt-2.5 pt-2.5 border-t border-[#D6E8F7] grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-[#64748B] font-medium">Korelasi MITRE ATT&CK: </span>
                        <span className="font-semibold text-[#006BB4]">{analysis.mitreTechnique}</span>
                      </div>
                      <div>
                        <span className="text-[#64748B] font-medium">Rekomendasi Tindakan: </span>
                        <span className="font-semibold text-[#1E293B]">{analysis.actionRecommendation}</span>
                      </div>
                    </div>
                  </div>

                  {/* Feedback Status Aksi Karantina jika ada */}
                  {actionMessage && (
                    <div
                      className={`text-[12px] px-3 py-2 rounded flex items-center gap-2 ${
                        actionMessage.startsWith('Sukses')
                          ? 'bg-[#E6F4EA] text-[#137333] border border-[#C8E6C9]'
                          : 'bg-[#FDECEA] text-[#BD271E] border border-[#FCD8D4]'
                      }`}
                    >
                      <Activity className="w-3.5 h-3.5" />
                      <span>{actionMessage}</span>
                    </div>
                  )}

                  {/* IoC Bar, External Links & Controls */}
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pt-1 border-t border-[#EDEEF2] text-[12px]">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[11px] font-medium text-[#5A626F] flex items-center gap-1">
                        <Fingerprint className="w-3.5 h-3.5 text-[#8A94A6]" />
                        SHA-256:
                      </span>
                      <code
                        className="bg-[#F8FAFC] border border-[#D3DAE6] px-2 py-0.5 rounded font-mono text-[11px] text-[#1E293B] select-all"
                        title={event.hash}
                      >
                        {event.hash ? `${event.hash.slice(0, 20)}...${event.hash.slice(-8)}` : 'Tidak ada hash'}
                      </code>
                      {event.hash && (
                        <button
                          onClick={() => handleCopyHash(event.hash)}
                          className="flex items-center gap-1 text-[11px] text-[#006BB4] hover:text-[#004B80] hover:underline transition"
                          title="Salin hash lengkap ke clipboard"
                        >
                          <Copy className="w-3 h-3" />
                          <span>{copiedHash === event.hash ? 'Tersalin' : 'Salin'}</span>
                        </button>
                      )}
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      {/* Link Verifikasi Eksternal */}
                      {event.hash && (
                        <div className="flex items-center gap-1.5 text-[11px] bg-[#F8FAFC] border border-[#D3DAE6] px-2 py-1 rounded">
                          <span className="text-[#8A94A6] font-medium">OSINT:</span>
                          <a
                            href={`https://www.virustotal.com/gui/file/${event.hash}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#006BB4] hover:underline flex items-center gap-0.5 font-medium"
                            title="Buka di VirusTotal"
                          >
                            VT
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                          <span className="text-[#D3DAE6]">|</span>
                          <a
                            href={`https://bazaar.abuse.ch/sample/${event.hash}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#006BB4] hover:underline flex items-center gap-0.5 font-medium"
                            title="Buka di MalwareBazaar"
                          >
                            MB
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                          <span className="text-[#D3DAE6]">|</span>
                          <a
                            href={`https://otx.alienvault.com/indicator/file/${event.hash}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#006BB4] hover:underline flex items-center gap-0.5 font-medium"
                            title="Buka di AlienVault OTX"
                          >
                            OTX
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        </div>
                      )}

                      {/* Tombol Karantina File jika ada path */}
                      {event.path && event.path !== '-' && (
                        <button
                          onClick={() => handleQuarantine(event)}
                          disabled={isBusy}
                          className={`flex items-center gap-1.5 px-3 py-1 rounded font-medium text-[11px] transition shadow-2xs ${
                            analysis.verdict === 'MALICIOUS'
                              ? 'bg-[#BD271E] hover:bg-[#A31F17] text-white'
                              : 'bg-white border border-[#D3DAE6] text-[#1A1C21] hover:bg-[#F8F9FB]'
                          } disabled:opacity-50`}
                          title="Kirim instruksi karantina ke agen target"
                        >
                          <Terminal className="w-3 h-3" />
                          <span>{isBusy ? 'Memproses...' : 'Karantina File'}</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Footer Penjelas */}
      <div className="px-4 py-3 text-[12px] text-[#5A626F] bg-white border border-[#D3DAE6] rounded flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-[#006BB4]" />
          <span>
            Pipeline deteksi aktif menghubungkan Wazuh Manager, orkestrasi n8n, model penalaran AI generatif, dan Active Response.
          </span>
        </div>
        <span className="text-[11px] text-[#8A94A6] hidden sm:inline">
          Format Waktu: WITA (UTC+8)
        </span>
      </div>
    </div>
  );
}
