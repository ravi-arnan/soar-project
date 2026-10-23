'use client';

import React, { useMemo, useState } from 'react';
import { Radio, FileText, ChevronRight, ChevronDown, Filter, X } from 'lucide-react';
import { WazuhFilterBar } from './WazuhFilterBar';
import { ExpandableCard } from './ExpandableCard';
import { PeriodFilter } from './PeriodFilter';
import { Pagination } from './Pagination';
import {
  formatWazuhTime,
  severityLevel,
  useEventHistory,
  periodToWindow,
} from '@/lib/fleet';
import { postCommand } from '@/lib/commands';
import type {
  EventHistoryQuery,
  FleetEvent,
  HistorySource,
  PeriodPreset,
  PeriodValue,
} from '@/lib/fleet';

interface SecurityEventsDashboardProps {
  onSelectAgent?: (agentId: string) => void;
  /** Buka view Agents (opsional; tombol Explore agent disembunyikan bila tak ada). */
  onOpenAgents?: () => void;
  onRefresh?: () => void;
  initialAgentId?: string;
  initialSeverity?: string[];
  initialTab?: 'dashboard' | 'events';
  initialPeriod?: PeriodPreset;
  initialSource?: HistorySource;
}

/** Warna seri untuk donut Top 5, disamakan dengan desain Wazuh. */
const TOP_AGENT_COLORS = ['#D9381E', '#00A389', '#006BB4', '#9B51E0', '#E2B93B'];

/** Keliling donut (r=38) pada desain lama. */
const DONUT_CIRCUMFERENCE = 240;

const DEFAULT_PERIOD_VALUE: PeriodValue = { preset: '7d', since: null, until: null };

function getMitreBadge(ruleId: string, description: string) {
  const d = description.toLowerCase();
  const r = ruleId.toLowerCase();
  if (r === '100004' || d.includes('ransomware') || d.includes('canary')) {
    return { id: 'T1486', name: 'Ransomware', bg: 'bg-[#FDE8E8]', text: 'text-[#BD271E]' };
  }
  if (r === '100003' || d.includes('double extension') || d.includes('masquerading')) {
    return { id: 'T1036.007', name: 'Masquerading', bg: 'bg-[#FEF3C7]', text: 'text-[#B45309]' };
  }
  if (r === '100002' || r === '100001' || d.includes('phishing')) {
    return { id: 'T1566.002', name: 'Phishing', bg: 'bg-[#EBF5FB]', text: 'text-[#006BB4]' };
  }
  if (r.startsWith('1100') || d.includes('powershell') || d.includes('lolbin') || d.includes('cmd.exe')) {
    return { id: 'T1059.001', name: 'Command & Script', bg: 'bg-[#F3E8FF]', text: 'text-[#7E22CE]' };
  }
  if (r === '550' || r === '554' || d.includes('syscheck') || d.includes('file added') || d.includes('checksum')) {
    return { id: 'T1565.001', name: 'FIM / File Mod', bg: 'bg-[#F1F5F9]', text: 'text-[#475569]' };
  }
  return null;
}

export function SecurityEventsDashboard({
  onSelectAgent,
  onOpenAgents,
  onRefresh,
  initialAgentId,
  initialSeverity,
  initialTab,
  initialPeriod,
  initialSource,
}: SecurityEventsDashboardProps) {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'events'>(
    () => initialTab || 'dashboard'
  );
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [activeFilters, setActiveFilters] = useState<string[]>([]);
  const [agentFilter, setAgentFilter] = useState<string | null>(initialAgentId || null);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>(
    () => initialSeverity || []
  );
  const [period, setPeriod] = useState<PeriodValue>(() =>
    initialPeriod
      ? { preset: initialPeriod, since: null, until: null }
      : DEFAULT_PERIOD_VALUE
  );
  const [source, setSource] = useState<HistorySource>(initialSource || 'all');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  /** Status antrean AR per baris: queued | gagal | mengirim. */
  const [arState, setArState] = useState<Record<string, string>>({});

  // Serialisasi array prop agar tidak memicu reset terus-menerus akibat referensi array baru
  const serializeArray = (arr?: string[]) => (arr ? [...arr].sort().join(',') : '');
  const [prevSeverityPropKey, setPrevSeverityPropKey] = useState(() => serializeArray(initialSeverity));
  const [prevTabProp, setPrevTabProp] = useState(initialTab);
  const [prevAgentProp, setPrevAgentProp] = useState(initialAgentId);
  const [prevPeriodProp, setPrevPeriodProp] = useState(initialPeriod);
  const [prevSourceProp, setPrevSourceProp] = useState(initialSource);

  const currentSeverityPropKey = serializeArray(initialSeverity);
  if (currentSeverityPropKey !== prevSeverityPropKey) {
    setPrevSeverityPropKey(currentSeverityPropKey);
    setSelectedSeverities(initialSeverity ? [...initialSeverity] : []);
    setPage(0);
  }

  if (initialTab !== prevTabProp) {
    setPrevTabProp(initialTab);
    setActiveTab(initialTab || 'dashboard');
  }

  if (initialAgentId !== prevAgentProp) {
    setPrevAgentProp(initialAgentId);
    setAgentFilter(initialAgentId || null);
    setPage(0);
  }

  if (initialPeriod !== prevPeriodProp) {
    setPrevPeriodProp(initialPeriod);
    setPeriod(
      initialPeriod
        ? { preset: initialPeriod, since: null, until: null }
        : DEFAULT_PERIOD_VALUE
    );
    setPage(0);
  }

  if (initialSource !== prevSourceProp) {
    setPrevSourceProp(initialSource);
    setSource(initialSource || 'all');
    setPage(0);
  }

  const timeWindow = useMemo(() => periodToWindow(period), [period]);
  const tokens = useMemo(
    () => [query, ...activeFilters].map((t) => t.trim()).filter(Boolean),
    [query, activeFilters]
  );

  const historyQuery = useMemo<EventHistoryQuery>(
    () => ({
      since: timeWindow.since,
      until: timeWindow.until,
      q: tokens,
      severity: selectedSeverities.length ? selectedSeverities : undefined,
      agentId: agentFilter || undefined,
      source,
      limit: rowsPerPage,
      offset: page * rowsPerPage,
    }),
    [
      timeWindow.since,
      timeWindow.until,
      tokens,
      selectedSeverities,
      agentFilter,
      source,
      rowsPerPage,
      page,
    ]
  );

  const {
    events: historyEvents,
    stats: historyStats,
    total,
    loading,
    error,
    indexerOk,
    indexerMatched,
    sources,
    refresh: refreshHistory,
  } = useEventHistory(historyQuery, 20000);

  /** Pemilihan filter keparahan yang deterministik (klik filter -> aktifkan; klik ulang -> reset ke Semua). */
  const handleSelectSeverityFilter = (sevs: string[], tab?: 'dashboard' | 'events') => {
    const currentKey = [...selectedSeverities].sort().join(',');
    const targetKey = [...sevs].sort().join(',');
    if (currentKey === targetKey && sevs.length > 0) {
      setSelectedSeverities([]);
    } else {
      setSelectedSeverities(sevs);
    }
    if (tab) {
      setActiveTab(tab);
    }
    setPage(0);
  };

  /** Terima search + chip filter dari WazuhFilterBar, reset ke halaman 1. */
  const handleSearch = (q: string, filters: string[]) => {
    setQuery(q);
    setActiveFilters(filters);
    setPage(0);
  };

  const handlePeriod = (value: PeriodValue) => {
    setPeriod(value);
    setPage(0);
  };

  const handleSource = (value: HistorySource) => {
    setSource(value);
    setPage(0);
  };

  const refresh = () => {
    refreshHistory();
    onRefresh?.();
  };

  const pageCount = Math.max(1, Math.ceil(total / rowsPerPage));

  // total bisa menyusut setelah filter/periode berubah; tarik page kembali ke rentang valid.
  if (page > pageCount - 1) {
    setPage(pageCount - 1);
  }
  const safePage = Math.min(page, pageCount - 1);

  // Riwayat (sudah terfilter + terpaginasi di server) -> baris tabel ala Wazuh.
  const visibleAlerts = useMemo(
    () =>
      historyEvents.map((e: FleetEvent) => ({
        id: e.id || JSON.stringify([e.ts, e.agent_id, e.hash, e.path, e.url]),
        time: formatWazuhTime(e.ts),
        agentId: e.agent_id || '-',
        agentName: e.agent || '-',
        hash: e.hash || '',
        rawPath: e.path && e.path !== '-' ? e.path : '',
        rawUrl: e.url || '',
        source: e.source || 'soar',
        description: e.ai
          ? `${e.path || '-'} — ${e.ai}`
          : e.rule_desc || e.path || e.status || '-',
        level: e.rule_level ?? severityLevel(e.severity),
        ruleId: e.rule_id || (e.severity || 'INFO').toUpperCase(),
      })),
    [historyEvents]
  );

  /** Unduh event yang tampil (halaman + filter aktif) sebagai CSV. */
  const exportCsv = () => {
    // Cegah formula injection di Excel/Sheets untuk sel yang diawali = + - @.
    const cell = (v: string | number) => {
      let s = String(v).replace(/"/g, '""');
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      return `"${s}"`;
    };
    const header = ['time', 'agent_id', 'agent_name', 'hash', 'description', 'level', 'rule', 'source'];
    const lines = visibleAlerts.map((r) =>
      [r.time, r.agentId, r.agentName, r.hash, r.description, r.level, r.ruleId, r.source]
        .map(cell)
        .join(',')
    );
    const csv = [header.join(','), ...lines].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const el = document.createElement('a');
    el.href = url;
    el.download = 'security-events.csv';
    el.click();
    URL.revokeObjectURL(url);
  };

  /** Extract domain dari URL event phishing (untuk sinkhole). */
  function domainOf(url: string): string {
    try {
      const h = new URL(url).hostname;
      if (h && /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(h)) return h;
    } catch {}
    const m = url.match(/https?:\/\/([^/:?\s#]+)/i);
    return m ? m[1] : '';
  }

  /** Antrekan perintah ke agent via fleet-monitor (di-poll agent, keluar-saja). */
  async function queueCommand(
    rowId: string,
    agentId: string,
    action: 'quarantine' | 'restore' | 'sinkhole',
    target: string
  ) {
    const label =
      action === 'quarantine'
        ? `karantina file ${target}`
        : action === 'restore'
        ? `pulihkan file ${target}`
        : `sinkhole domain ${target}`;
    if (!window.confirm(`Antrekan ${label} di agent ${agentId}?`)) return;
    setArState((s) => ({ ...s, [rowId]: 'mengirim...' }));
    try {
      const r = await postCommand({ agent_id: agentId, action, target });
      const j = await r.json();
      setArState((s) => ({
        ...s,
        [rowId]: r.ok && j.status === 'queued' ? 'queued ✓' : `gagal: ${j.error || r.status}`,
      }));
    } catch {
      setArState((s) => ({ ...s, [rowId]: 'gagal: jaringan' }));
    }
  }

  const sev = historyStats.severity;
  const statsTotal =
    sev.CRITICAL + sev.HIGH + sev.MEDIUM + sev.UNVERIFIED + sev.INFO;
  const topAgents = historyStats.top_agents.map((a) => [a.key, a.count] as [string, number]);
  const topPaths = historyStats.top_paths.map((p) => [p.key, p.count] as [string, number]);
  const topPathTotal = topPaths.reduce((sum, [, n]) => sum + n, 0) || 1;
  const topPathArcs = topPaths.map(([, n]) => Math.round((n / topPathTotal) * DONUT_CIRCUMFERENCE));
  const topTotal = topAgents.reduce((sum, [, n]) => sum + n, 0) || 1;
  const topArcs = topAgents.map(([, n]) => Math.round((n / topTotal) * DONUT_CIRCUMFERENCE));
  const dailyHits = historyStats.daily.slice(-30).map((d) => ({
    label: d.date.slice(5),
    count: d.count,
  }));
  const dailyMax = Math.max(1, ...dailyHits.map((d) => d.count));

  return (
    <div className="space-y-4">
      {/* Subheader Tabs & Actions */}
      <div className="flex items-center justify-between border-b border-[#D3DAE6] pb-2">
        <div className="flex items-center gap-6 text-[13px]">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`pb-2.5 -mb-2 font-medium transition-colors ${
              activeTab === 'dashboard'
                ? 'border-b-2 border-[#006BB4] text-[#006BB4]'
                : 'text-[#5A626F] hover:text-[#1A1C21]'
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab('events')}
            className={`pb-2.5 -mb-2 font-medium transition-colors ${
              activeTab === 'events'
                ? 'border-b-2 border-[#006BB4] text-[#006BB4]'
                : 'text-[#5A626F] hover:text-[#1A1C21]'
            }`}
          >
            Events
          </button>
        </div>

        <div className="flex items-center gap-4 text-[12px]">
          {onOpenAgents && (
            <button
              onClick={onOpenAgents}
              className="flex items-center gap-1.5 text-[#006BB4] hover:underline font-medium"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Explore agent</span>
            </button>
          )}
          <button
            onClick={exportCsv}
            title="Unduh event yang tampil sebagai CSV"
            className="flex items-center gap-1.5 text-[#006BB4] hover:underline font-medium"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Generate report</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <WazuhFilterBar
        onRefresh={refresh}
        onSearch={handleSearch}
        filters={activeFilters}
        agentFilter={agentFilter || undefined}
        onClearAgentFilter={() => {
          setAgentFilter(null);
          setPage(0);
        }}
        periodSlot={
          <PeriodFilter
            value={period}
            onChange={handlePeriod}
            source={source}
            onSourceChange={handleSource}
          />
        }
      />

      {/* Status sumber riwayat */}
      <div className="text-[11px] text-[#8A94A6] -mt-2">
        Riwayat: {total.toLocaleString('en-US')} event · pipeline SOAR {sources.soar} ·
        Wazuh {sources.wazuh}
        {indexerMatched !== null && indexerMatched > sources.wazuh && (
          <span className="text-[#B25E09]">
            {' '}(dari {indexerMatched.toLocaleString('en-US')} yang cocok)
          </span>
        )}
        {indexerOk === false && <span className="text-[#BD271E]"> · indexer tidak terjangkau</span>}
        {error && <span className="text-[#BD271E]"> · {error}</span>}
      </div>

      {activeTab === 'dashboard' && (
        <>
          {/* Top 4 Metric KPI Counters — interaktif: klik untuk memfilter keparahan di tab Events. */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
            <button
              type="button"
              onClick={() => handleSelectSeverityFilter([], 'events')}
              className="p-2 rounded hover:bg-[#F5F7FA] transition-colors text-center group cursor-pointer border border-transparent hover:border-[#D3DAE6]"
              title="Tampilkan semua security alerts di tab Events"
            >
              <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#1A1C21]">Total</div>
              <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">
                {statsTotal.toLocaleString('en-US')}
              </div>
              <div className="text-[10px] text-[#8A94A6] group-hover:text-[#006BB4] mt-0.5">
                Buka tab Events &rarr;
              </div>
            </button>
            <button
              type="button"
              onClick={() => handleSelectSeverityFilter(['CRITICAL'], 'events')}
              className="p-2 rounded hover:bg-[#FDF3F2] transition-colors text-center group cursor-pointer border border-transparent hover:border-[#F5C2C0]"
              title="Filter hanya Critical alerts (Level 12+) di tab Events"
            >
              <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#BD271E]">Critical alerts (Level 12+)</div>
              <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">
                {sev.CRITICAL.toLocaleString('en-US')}
              </div>
              <div className="text-[10px] text-[#8A94A6] group-hover:text-[#BD271E] mt-0.5">
                Filter Critical di Events &rarr;
              </div>
            </button>
            <button
              type="button"
              onClick={() => handleSelectSeverityFilter(['HIGH'], 'events')}
              className="p-2 rounded hover:bg-[#FEF6E8] transition-colors text-center group cursor-pointer border border-transparent hover:border-[#F5D9A8]"
              title="Filter hanya High severity threats di tab Events"
            >
              <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#D97706]">High severity threats</div>
              <div className="text-[32px] font-semibold text-[#D97706] leading-tight mt-1">
                {sev.HIGH.toLocaleString('en-US')}
              </div>
              <div className="text-[10px] text-[#8A94A6] group-hover:text-[#D97706] mt-0.5">
                Filter High di Events &rarr;
              </div>
            </button>
            <button
              type="button"
              onClick={() => handleSelectSeverityFilter(['MEDIUM'], 'events')}
              className="p-2 rounded hover:bg-[#F0FAF7] transition-colors text-center group cursor-pointer border border-transparent hover:border-[#B2E6DC]"
              title="Filter hanya Medium severity events di tab Events"
            >
              <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#00A389]">Medium severity events</div>
              <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">
                {sev.MEDIUM.toLocaleString('en-US')}
              </div>
              <div className="text-[10px] text-[#8A94A6] group-hover:text-[#00A389] mt-0.5">
                Filter Medium di Events &rarr;
              </div>
            </button>
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Card 1: Severity breakdown donut */}
            <ExpandableCard title="Severity breakdown">
              <div className="flex items-center justify-center gap-6 h-56">
                <div className="relative w-40 h-40 flex items-center justify-center">
                  <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                    <circle cx="50" cy="50" r="38" fill="none" stroke="#EBEFF5" strokeWidth="18" />
                    {(() => {
                      const totalSev = sev.CRITICAL + sev.HIGH + sev.MEDIUM + sev.UNVERIFIED || 1;
                      const items = [
                        { label: 'CRITICAL', count: sev.CRITICAL, color: '#BD271E' },
                        { label: 'HIGH', count: sev.HIGH, color: '#D97706' },
                        { label: 'MEDIUM', count: sev.MEDIUM, color: '#F5A623' },
                        { label: 'UNVERIFIED', count: sev.UNVERIFIED, color: '#64748B' },
                      ];
                      let offset = 0;
                      const arcs: Array<{ label: string; color: string; len: number; offset: number }> = [];
                      const circum = 238.76;
                      for (const item of items) {
                        const len = (item.count / totalSev) * circum;
                        if (len > 0) arcs.push({ ...item, len, offset });
                        offset += len;
                      }
                      return arcs.map((a) =>
                        a.len >= 1 ? (
                          <circle
                            key={a.label}
                            cx="50"
                            cy="50"
                            r="38"
                            fill="none"
                            stroke={a.color}
                            strokeWidth="18"
                            strokeDasharray={`${a.len} ${circum - a.len}`}
                            strokeDashoffset={`-${a.offset}`}
                          />
                        ) : null
                      );
                    })()}
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-[20px] font-bold text-[#1A1C21]">
                      {sev.CRITICAL + sev.HIGH + sev.MEDIUM + sev.UNVERIFIED}
                    </span>
                  </div>
                </div>

                <div className="text-[11px] space-y-1.5 text-[#5A626F]">
                  {[
                    { label: 'CRITICAL', count: sev.CRITICAL, color: '#BD271E' },
                    { label: 'HIGH', count: sev.HIGH, color: '#D97706' },
                    { label: 'MEDIUM', count: sev.MEDIUM, color: '#F5A623' },
                    { label: 'UNVERIFIED', count: sev.UNVERIFIED, color: '#64748B' },
                  ].map((s) =>
                    s.count > 0 ? (
                      <button
                        key={s.label}
                        type="button"
                        onClick={() => handleSelectSeverityFilter([s.label], 'events')}
                        className="flex items-center gap-2 hover:opacity-80 transition-opacity cursor-pointer text-left w-full group"
                        title={`Filter ${s.label} di tab Events`}
                      >
                        <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: s.color }} />
                        <span className="group-hover:underline">{s.label}</span>
                        <span className="font-semibold">{s.count}</span>
                        <span className="text-[10px] text-[#8A94A6] ml-auto group-hover:text-[#006BB4]">&rarr;</span>
                      </button>
                    ) : null
                  )}
                </div>
              </div>
            </ExpandableCard>

            {/* Card 2: Top paths */}
            <ExpandableCard title="Top paths">
              <div className="flex items-center justify-center gap-6 h-56">
                <div className="relative w-40 h-40 flex items-center justify-center">
                  <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                    <circle cx="50" cy="50" r="38" fill="none" stroke="#EBEFF5" strokeWidth="18" />
                    {topPathArcs.map((len, i) => {
                      const offset = topPathArcs.slice(0, i).reduce((a, b) => a + b, 0);
                      return len > 0 ? (
                        <circle
                          key={i}
                          cx="50"
                          cy="50"
                          r="38"
                          fill="none"
                          stroke={TOP_AGENT_COLORS[i % TOP_AGENT_COLORS.length]}
                          strokeWidth="18"
                          strokeDasharray={`${len} ${DONUT_CIRCUMFERENCE - len}`}
                          strokeDashoffset={`-${offset}`}
                        />
                      ) : null;
                    })}
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-[20px] font-bold text-[#1A1C21]">
                      {topPaths.reduce((s, [, n]) => s + n, 0)}
                    </span>
                  </div>
                </div>

                <div className="text-[11px] space-y-1 text-[#5A626F] overflow-y-auto max-h-48 pr-2">
                  {topPaths.length ? (
                    topPaths.map(([path, n], i) => (
                      <div key={path} className="flex items-center gap-2">
                        <span
                          className="w-2.5 h-2.5 rounded-full shrink-0"
                          style={{ backgroundColor: TOP_AGENT_COLORS[i % TOP_AGENT_COLORS.length] }}
                        ></span>
                        <span className="truncate max-w-[160px] font-mono" title={path}>
                          {path.split(/[/\\]/).pop()}
                        </span>
                        <span className="font-semibold">{n}</span>
                      </div>
                    ))
                  ) : (
                    <span className="text-[#8A94A6]">belum ada event</span>
                  )}
                </div>
              </div>
            </ExpandableCard>

            {/* Card 3: Top 5 Agents */}
            <ExpandableCard title="Top 5 agents">
              <div className="flex items-center justify-center gap-6 h-56">
                <div className="relative w-40 h-40 flex items-center justify-center">
                  <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                    <circle cx="50" cy="50" r="38" fill="none" stroke="#EBEFF5" strokeWidth="18" />
                    {topArcs.map((len, i) => {
                      const offset = topArcs.slice(0, i).reduce((a, b) => a + b, 0);
                      return (
                        <circle
                          key={i}
                          cx="50"
                          cy="50"
                          r="38"
                          fill="none"
                          stroke={TOP_AGENT_COLORS[i % TOP_AGENT_COLORS.length]}
                          strokeWidth="18"
                          strokeDasharray={`${len} ${DONUT_CIRCUMFERENCE - len}`}
                          strokeDashoffset={`-${offset}`}
                        />
                      );
                    })}
                  </svg>
                </div>

                <div className="text-[11px] space-y-1.5 text-[#5A626F]">
                  {topAgents.length ? (
                    topAgents.map(([name, count], i) => (
                      <div key={name} className="flex items-center gap-2">
                        <span
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: TOP_AGENT_COLORS[i % TOP_AGENT_COLORS.length] }}
                        ></span>
                        <span className="truncate max-w-[140px]" title={name}>{name}</span>
                        <span className="font-semibold">{count}</span>
                      </div>
                    ))
                  ) : (
                    <span className="text-[#8A94A6]">belum ada event</span>
                  )}
                </div>
              </div>
            </ExpandableCard>

            {/* Card 4: Alerts evolution (histogram per hari, mengikuti rentang) */}
            <ExpandableCard title="Alerts evolution">
              <div className="flex items-center justify-between gap-4 h-56">
                <div className="flex-1 h-full flex flex-col justify-end">
                  <div className="h-44 flex items-end justify-between gap-1 border-b border-[#D3DAE6] pb-1">
                    {dailyHits.length ? (
                      dailyHits.map((d) => (
                        <div
                          key={d.label}
                          className="flex-1 flex flex-col justify-end items-center h-full"
                          title={`${d.label}: ${d.count} event`}
                        >
                          <div
                            style={{
                              height: `${Math.round((d.count / dailyMax) * 100)}%`,
                              minHeight: d.count > 0 ? 4 : 0,
                            }}
                            className="bg-[#006BB4] w-full"
                          ></div>
                        </div>
                      ))
                    ) : (
                      <span className="text-[11px] text-[#8A94A6] self-center">belum ada event</span>
                    )}
                  </div>
                  {dailyHits.length > 0 && (
                    <div className="flex justify-between text-[10px] text-[#8A94A6] mt-2">
                      <span>{dailyHits[0]?.label}</span>
                      <span>{dailyHits[Math.floor(dailyHits.length / 2)]?.label}</span>
                      <span>{dailyHits[dailyHits.length - 1]?.label}</span>
                    </div>
                  )}
                </div>
              </div>
            </ExpandableCard>
          </div>
        </>
      )}

      {/* Quick Severity Filter Bar & Active Filter Chips */}
      {(() => {
        const isAll = selectedSeverities.length === 0;
        const isCritAndHigh =
          selectedSeverities.length === 2 &&
          selectedSeverities.includes('CRITICAL') &&
          selectedSeverities.includes('HIGH');
        const isCritOnly =
          selectedSeverities.length === 1 && selectedSeverities.includes('CRITICAL');
        const isHighOnly =
          selectedSeverities.length === 1 && selectedSeverities.includes('HIGH');
        const isMedOnly =
          selectedSeverities.length === 1 && selectedSeverities.includes('MEDIUM');

        return (
          <div className="bg-white border border-[#D3DAE6] rounded p-2.5 flex flex-wrap items-center justify-between gap-2.5 text-[12px]">
            <div className="flex flex-wrap items-center gap-1.5">
              <div className="flex items-center gap-1 text-[#5A626F] font-semibold text-[11px] mr-1">
                <Filter className="w-3.5 h-3.5 text-[#5A626F]" />
                <span>Tingkat Keparahan:</span>
              </div>

              <button
                type="button"
                onClick={() => handleSelectSeverityFilter([])}
                className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  isAll
                    ? 'bg-[#1A1C21] text-white shadow-xs'
                    : 'bg-[#F0F4F8] text-[#5A626F] hover:bg-[#E1E6EB]'
                }`}
              >
                Semua
              </button>

              <button
                type="button"
                onClick={() => handleSelectSeverityFilter(['CRITICAL', 'HIGH'])}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                  isCritAndHigh
                    ? 'bg-[#BD271E] text-white shadow-xs'
                    : 'bg-[#FDE8E8] text-[#BD271E] hover:bg-[#FBD5D5]'
                }`}
                title="Tampilkan alert Critical dan High"
              >
                Critical + High ({sev.CRITICAL + sev.HIGH})
              </button>

              <button
                type="button"
                onClick={() => handleSelectSeverityFilter(['CRITICAL'])}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                  isCritOnly
                    ? 'bg-[#BD271E] text-white shadow-xs'
                    : 'bg-[#FDF3F2] text-[#BD271E] hover:bg-[#FDE8E8]'
                }`}
                title="Filter hanya alert Critical"
              >
                Critical ({sev.CRITICAL})
              </button>

              <button
                type="button"
                onClick={() => handleSelectSeverityFilter(['HIGH'])}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                  isHighOnly
                    ? 'bg-[#D97706] text-white shadow-xs'
                    : 'bg-[#FEF6E8] text-[#D97706] hover:bg-[#FDEFD4]'
                }`}
                title="Filter hanya alert High"
              >
                High ({sev.HIGH})
              </button>

              <button
                type="button"
                onClick={() => handleSelectSeverityFilter(['MEDIUM'])}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                  isMedOnly
                    ? 'bg-[#00A389] text-white shadow-xs'
                    : 'bg-[#F0FAF7] text-[#00A389] hover:bg-[#E1F7F2]'
                }`}
                title="Filter hanya alert Medium"
              >
                Medium ({sev.MEDIUM})
              </button>
            </div>

            {selectedSeverities.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-[#5A626F]">
                  Menampilkan {total} event (Keparahan:{' '}
                  <span className="font-semibold text-[#1A1C21]">
                    {selectedSeverities.join(', ')}
                  </span>
                  )
                </span>
                <button
                  type="button"
                  onClick={() => handleSelectSeverityFilter([])}
                  className="inline-flex items-center gap-1 text-[11px] text-[#BD271E] hover:text-[#9E1F18] font-medium bg-[#FDE8E8] hover:bg-[#FBD5D5] px-2 py-0.5 rounded cursor-pointer transition-colors"
                  title="Hapus filter keparahan"
                >
                  <X className="w-3 h-3" />
                  <span>Reset filter</span>
                </button>
              </div>
            )}
          </div>
        );
      })()}

      {/* Security Alerts Data Table Card */}
      <ExpandableCard title="Security Alerts">
        <div className="overflow-x-auto border border-[#EBEFF5] rounded">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F] font-semibold select-none">
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-3">Time ↓</th>
                <th className="py-2.5 px-3">Sumber</th>
                <th className="py-2.5 px-3">Agent</th>
                <th className="py-2.5 px-3">Agent name</th>
                <th className="py-2.5 px-3">Hash (VT)</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3 text-center">Level</th>
                <th className="py-2.5 px-3 text-right">Rule ID</th>
                <th className="py-2.5 px-3 text-right">Aksi</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEFF5]">
              {!visibleAlerts.length && (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-[#8A94A6]">
                    {loading ? (
                      'memuat riwayat…'
                    ) : (
                      <div className="space-y-1">
                        <div>
                          {tokens.length
                            ? `tidak ada event cocok "${tokens.join(' + ')}"${
                                selectedSeverities.length
                                  ? ` dengan keparahan ${selectedSeverities.join(', ')}`
                                  : ''
                              }`
                            : selectedSeverities.length
                            ? `tidak ada event dengan keparahan ${selectedSeverities.join(', ')} pada periode ini`
                            : 'belum ada event pada periode ini'}
                        </div>
                        {selectedSeverities.length > 0 && (
                          <div>
                            <button
                              type="button"
                              onClick={() => handleSelectSeverityFilter([])}
                              className="text-[11px] text-[#006BB4] hover:underline font-medium cursor-pointer"
                            >
                              Reset filter keparahan &rarr;
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              )}
              {visibleAlerts.map((row) => {
                const isExpanded = expandedRow === row.id;
                const mitre = getMitreBadge(row.ruleId, row.description);
                return (
                  <React.Fragment key={row.id}>
                    <tr className="hover:bg-[#F8FAFC] transition-colors">
                      <td className="py-2 px-3 text-center">
                        <button
                          type="button"
                          aria-label={isExpanded ? 'Tutup detail alert' : 'Buka detail alert'}
                          onClick={() => setExpandedRow(isExpanded ? null : row.id)}
                          className="text-[#5A626F] hover:text-[#1A1C21]"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </td>
                      <td className="py-2 px-3 text-[#5A626F] whitespace-nowrap">{row.time}</td>
                      <td className="py-2 px-3">
                        <span
                          className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            row.source === 'wazuh'
                              ? 'bg-[#F0F4F8] text-[#5A626F]'
                              : 'bg-[#EBF5FB] text-[#006BB4]'
                          }`}
                        >
                          {row.source === 'wazuh' ? 'Wazuh' : 'SOAR'}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-medium">
                        <button
                          onClick={() => onSelectAgent?.(row.agentId)}
                          className="text-[#006BB4] hover:underline"
                        >
                          {row.agentId}
                        </button>
                      </td>
                      <td className="py-2 px-3 text-[#1A1C21] font-medium whitespace-nowrap">
                        {row.agentName}
                      </td>
                      <td className="py-2 px-3 text-[#006BB4] font-mono text-[12px]">
                        {row.hash ? (
                          <a
                            href={`https://www.virustotal.com/gui/file/${row.hash}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="hover:underline"
                            title={row.hash}
                          >
                            {row.hash.slice(0, 16)}...
                          </a>
                        ) : (
                          '-'
                        )}
                      </td>
                      <td className="py-2 px-3 text-[#1A1C21] max-w-md">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {mitre && (
                            <span
                              className={`inline-flex shrink-0 items-center px-1.5 py-0.5 rounded text-[10px] font-semibold font-mono ${mitre.bg} ${mitre.text}`}
                              title={`${mitre.id} - ${mitre.name}`}
                            >
                              {mitre.id}
                            </span>
                          )}
                          <span className="truncate">{row.description}</span>
                        </div>
                      </td>
                      <td className="py-2 px-3 text-center">
                        <span
                          className={`inline-block px-1.5 py-0.5 rounded text-[11px] font-semibold ${
                            row.level >= 12
                              ? 'bg-[#FDE8E8] text-[#BD271E]'
                              : row.level >= 7
                              ? 'bg-[#FEF08A] text-[#854D0E]'
                              : 'bg-[#EBF5FB] text-[#006BB4]'
                          }`}
                        >
                          {row.level}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right font-medium text-[#5A626F]">
                        {row.ruleId}
                      </td>
                      <td className="py-2 px-3 text-right whitespace-nowrap">
                        {(() => {
                          const st = arState[row.id];
                          const dom = row.rawUrl ? domainOf(row.rawUrl) : '';
                          return (
                            <span className="inline-flex items-center gap-1.5">
                              {row.rawPath && (
                                <>
                                  <button
                                    type="button"
                                    disabled={Boolean(st) || row.agentId === '-'}
                                    onClick={() =>
                                      queueCommand(row.id, row.agentId, 'quarantine', row.rawPath)
                                    }
                                    title={`Karantina ${row.rawPath} di agent ${row.agentId}`}
                                    className="text-[11px] font-medium text-[#BD271E] border border-[#F5C2C0] bg-[#FDF3F2] hover:bg-[#FDE8E8] px-1.5 py-0.5 rounded disabled:opacity-50"
                                  >
                                    Karantina
                                  </button>
                                  <button
                                    type="button"
                                    disabled={Boolean(st) || row.agentId === '-'}
                                    onClick={() =>
                                      queueCommand(row.id, row.agentId, 'restore', row.rawPath)
                                    }
                                    title={`Pulihkan ${row.rawPath} dari karantina di agent ${row.agentId}`}
                                    className="text-[11px] font-medium text-[#006BB4] border border-[#B8D5E5] bg-[#F0F7FC] hover:bg-[#E1EFF8] px-1.5 py-0.5 rounded disabled:opacity-50"
                                  >
                                    Pulihkan
                                  </button>
                                </>
                              )}
                              {dom && (
                                <button
                                  type="button"
                                  disabled={Boolean(st) || row.agentId === '-'}
                                  onClick={() => queueCommand(row.id, row.agentId, 'sinkhole', dom)}
                                  title={`Sinkhole ${dom} di agent ${row.agentId}`}
                                  className="text-[11px] font-medium text-[#B25E09] border border-[#F5D9A8] bg-[#FEF6E8] hover:bg-[#FDEFD4] px-1.5 py-0.5 rounded disabled:opacity-50"
                                >
                                  Blokir
                                </button>
                              )}
                              {st && (
                                <span role="status" aria-live="polite" className="text-[11px] text-[#5A626F]">
                                  {st}
                                </span>
                              )}
                              {!row.rawPath && !dom && <span className="text-[#8A94A6]">-</span>}
                            </span>
                          );
                        })()}
                      </td>
                    </tr>

                    {/* Expandable row with JSON details */}
                    {isExpanded && (
                      <tr className="bg-[#F8FAFC]">
                        <td colSpan={10} className="p-4">
                          <div className="bg-white border border-[#D3DAE6] rounded p-3 text-[11px] font-mono text-[#1A1C21] space-y-1">
                            <div className="text-[12px] font-bold text-[#006BB4] mb-2 font-sans">
                              Alert Details: {row.ruleId}
                            </div>
                            <div><strong>timestamp:</strong> {row.time}</div>
                            <div><strong>agent.id:</strong> &quot;{row.agentId}&quot;</div>
                            <div><strong>agent.name:</strong> &quot;{row.agentName}&quot;</div>
                            <div><strong>rule.level:</strong> {row.level}</div>
                            <div><strong>rule.description:</strong> &quot;{row.description}&quot;</div>
                            <div><strong>location:</strong> &quot;{row.source === 'wazuh' ? 'wazuh-alerts (indexer)' : 'wazuh-alerts'}&quot;</div>
                            {mitre && (
                              <div className="pt-1.5 border-t border-[#EDEEF2] mt-2 flex items-center gap-2 font-sans text-[11px]">
                                <span className="font-semibold text-[#5A626F]">MITRE Technique:</span>
                                <span className={`px-1.5 py-0.5 rounded font-mono font-semibold ${mitre.bg} ${mitre.text}`}>
                                  {mitre.id}
                                </span>
                                <span className="text-[#1A1C21] font-medium">{mitre.name}</span>
                              </div>
                            )}
                            {row.hash && (
                              <div className="pt-1.5 border-t border-[#EDEEF2] mt-2 flex items-center gap-2 font-sans text-[11px]">
                                <span className="font-semibold text-[#5A626F]">Investigasi Intel:</span>
                                <a
                                  href={`https://www.virustotal.com/gui/file/${row.hash}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-[#006BB4] hover:underline"
                                >
                                  VirusTotal ↗
                                </a>
                                <span className="text-[#D3DAE6]">|</span>
                                <a
                                  href={`https://bazaar.abuse.ch/sample/${row.hash}/`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-[#006BB4] hover:underline"
                                >
                                  MalwareBazaar ↗
                                </a>
                                <span className="text-[#D3DAE6]">|</span>
                                <a
                                  href={`https://otx.alienvault.com/indicator/file/${row.hash}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-[#006BB4] hover:underline"
                                >
                                  AlienVault OTX ↗
                                </a>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination bar (server-side) */}
        <Pagination
          page={safePage}
          pageCount={pageCount}
          total={total}
          rowsPerPage={rowsPerPage}
          onPageChange={setPage}
          onRowsChange={setRowsPerPage}
        />
      </ExpandableCard>
    </div>
  );
}
