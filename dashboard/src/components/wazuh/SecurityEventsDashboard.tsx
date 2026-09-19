'use client';

import React, { useMemo, useState } from 'react';
import {
  Radio,
  FileText,
  ChevronRight,
  ChevronDown,
  Info,
  List,
} from 'lucide-react';
import { WazuhFilterBar } from './WazuhFilterBar';
import { ExpandableCard } from './ExpandableCard';
import { formatWazuhTime, severityLevel } from '@/lib/fleet';
import type { FleetEvent, FleetStats } from '@/lib/fleet';

interface SecurityEventsDashboardProps {
  onSelectAgent?: (agentId: string) => void;
  /** Buka view Agents (opsional; tombol Explore agent disembunyikan bila tak ada). */
  onOpenAgents?: () => void;
  /** Event live dari /api/events (heartbeat agent + webhook n8n). */
  events: FleetEvent[];
  /** Ringkasan severity dari /api/fleet. */
  stats: FleetStats;
  onRefresh?: () => void;
}

/** Warna seri untuk donut Top 5 agents, disamakan dengan desain Wazuh. */
const TOP_AGENT_COLORS = ['#D9381E', '#00A389', '#006BB4', '#9B51E0', '#E2B93B'];

/** Keliling donut (r=38) pada CS5 lama: 60+50+40+30 = 180 dari skala 240. */
const DONUT_CIRCUMFERENCE = 240;

export function SecurityEventsDashboard({
  onSelectAgent,
  onOpenAgents,
  events,
  stats,
  onRefresh,
}: SecurityEventsDashboardProps) {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'events'>('dashboard');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [query, setQuery] = useState('');
  const [activeFilters, setActiveFilters] = useState<string[]>([]);
  /** Rentang waktu event dalam jam (null = semua). */
  const [rangeHours, setRangeHours] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  /** Status antrean AR per baris: queued | gagal | mengirim. */
  const [arState, setArState] = useState<Record<number, string>>({});

  /** Terima search + chip filter dari WazuhFilterBar, reset ke halaman 1. */
  const handleSearch = (q: string, filters: string[]) => {
    setQuery(q);
    setActiveFilters(filters);
    setPage(0);
  };

  const handleRange = (h: number | null) => {
    setRangeHours(h);
    setPage(0);
  };

  // Event dalam rentang waktu terpilih (berlaku untuk tabel + grafik).
  const rangedEvents = useMemo(() => {
    if (rangeHours === null) return events;
    const cutoff = Date.now() - rangeHours * 3600 * 1000;
    return events.filter((e) => {
      const t = new Date(e.ts).getTime();
      return !Number.isNaN(t) && t >= cutoff;
    });
  }, [events, rangeHours]);

  /** Unduh event yang tampil (filter + rentang aktif) sebagai CSV. */
  const exportCsv = () => {
    const cell = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;
    const lines = visibleAlerts.map((r) =>
      [r.time, r.agentId, r.agentName, r.hash, r.description, r.level, r.ruleId].map(cell).join(',')
    );
    const blob = new Blob(
      [[['time', 'agent_id', 'agent_name', 'hash', 'description', 'level', 'rule'].join(','), ...lines].join('\n')],
      { type: 'text/csv' }
    );
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
  async function queueCommand(rowId: number, agentId: string, action: 'quarantine' | 'sinkhole', target: string) {
    const label = action === 'quarantine' ? `karantina file ${target}` : `sinkhole domain ${target}`;
    if (!window.confirm(`Antrekan ${label} di agent ${agentId}?`)) return;
    setArState((s) => ({ ...s, [rowId]: 'mengirim...' }));
    try {
      const r = await fetch('/api/commands', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_id: agentId, action, target, by: 'dashboard' }),
      });
      const j = await r.json();
      setArState((s) => ({ ...s, [rowId]: r.ok && j.status === 'queued' ? 'queued ✓' : `gagal: ${j.error || r.status}` }));
    } catch (e) {
      setArState((s) => ({ ...s, [rowId]: 'gagal: jaringan' }));
    }
  }

  // Event live -> baris tabel ala Wazuh. `level` mengikuti bucket severity fleet
  // (CRITICAL=12, HIGH=8, MEDIUM=5, UNVERIFIED=4, INFO=3).
  const alertsData = useMemo(
    () =>
      rangedEvents.map((e, i) => ({
        id: i + 1,
        time: formatWazuhTime(e.ts),
        agentId: e.agent_id || '-',
        agentName: e.agent || '-',
        hash: e.hash || '',
        rawPath: e.path && e.path !== '-' ? e.path : '',
        rawUrl: e.url || '',
        techniques: '-',
        tactics: '-',
        description: e.ai ? `${e.path || '-'} — ${e.ai}` : e.path || e.status || '-',
        level: severityLevel(e.severity),
        ruleId: (e.severity || 'INFO').toUpperCase(),
      })),
    [rangedEvents]
  );

  // Filter search + chip dari WazuhFilterBar: tiap token harus cocok (AND)
  // ke deskripsi / agent / rule.
  const visibleAlerts = useMemo(() => {
    const tokens = [query, ...activeFilters]
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
    if (!tokens.length) return alertsData;
    return alertsData.filter((r) => {
      const hay = `${r.description} ${r.agentName} ${r.agentId} ${r.ruleId}`.toLowerCase();
      return tokens.every((t) => hay.includes(t));
    });
  }, [alertsData, query, activeFilters]);

  // Pagination: potong hasil filter per halaman.
  const pageCount = Math.max(1, Math.ceil(visibleAlerts.length / rowsPerPage));
  const safePage = Math.min(page, pageCount - 1);
  const pagedAlerts = visibleAlerts.slice(safePage * rowsPerPage, safePage * rowsPerPage + rowsPerPage);

  // Top 5 agent menurut jumlah event (dalam rentang aktif).
  const topAgents = useMemo(() => {
    const counts = new Map<string, number>();
    rangedEvents.forEach((e) => {
      const key = e.agent || '-';
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [rangedEvents]);

  // Top 5 path menurut jumlah event (dalam rentang aktif).
  const topPaths = useMemo(() => {
    const counts = new Map<string, number>();
    rangedEvents.forEach((e) => {
      if (e.path && e.path !== '-') counts.set(e.path, (counts.get(e.path) || 0) + 1);
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [rangedEvents]);
  const topPathTotal = topPaths.reduce((sum, [, n]) => sum + n, 0) || 1;
  const topPathArcs = topPaths.map(([, n]) => Math.round((n / topPathTotal) * DONUT_CIRCUMFERENCE));

  // Histogram event per hari, 14 hari terakhir (dalam rentang aktif).
  const dailyHits = useMemo(() => {
    const days: { label: string; count: number }[] = [];
    const now = new Date();
    for (let i = 13; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
      days.push({ label: `${d.getDate()}/${d.getMonth() + 1}`, count: 0 });
    }
    rangedEvents.forEach((e) => {
      const t = new Date(e.ts).getTime();
      if (Number.isNaN(t)) return;
      const idx = 13 - Math.floor((new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime() - new Date(new Date(t).getFullYear(), new Date(t).getMonth(), new Date(t).getDate()).getTime()) / 86400000);
      if (idx >= 0 && idx < 14) days[idx].count += 1;
    });
    return days;
  }, [rangedEvents]);
  const dailyMax = Math.max(1, ...dailyHits.map((d) => d.count));

  const topTotal = topAgents.reduce((sum, [, n]) => sum + n, 0) || 1;
  const topArcs = topAgents.map(([, n]) => Math.round((n / topTotal) * DONUT_CIRCUMFERENCE));

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
        onRefresh={onRefresh}
        onSearch={handleSearch}
        dateRange={rangeHours}
        onDateRange={handleRange}
      />

      {activeTab === 'dashboard' && (
      <>
      {/* Top 4 Metric KPI Counters — angka live dari /api/fleet.
          Bucket severity fleet dipetakan ke 4 tile Wazuh (CRITICAL / HIGH / MEDIUM). */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Total</div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">
            {stats.events_total.toLocaleString('en-US')}
          </div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Level 12 or above alerts</div>
          <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">
            {stats.severity.CRITICAL.toLocaleString('en-US')}
          </div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Authentication failure</div>
          <div className="text-[32px] font-semibold text-[#D97706] leading-tight mt-1">
            {stats.severity.HIGH.toLocaleString('en-US')}
          </div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Authentication success</div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">
            {stats.severity.MEDIUM.toLocaleString('en-US')}
          </div>
        </div>
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
                  const sev = stats.severity;
                  const total = sev.CRITICAL + sev.HIGH + sev.MEDIUM + sev.UNVERIFIED || 1;
                  const items = [
                    { label: 'CRITICAL', count: sev.CRITICAL, color: '#BD271E' },
                    { label: 'HIGH', count: sev.HIGH, color: '#D97706' },
                    { label: 'MEDIUM', count: sev.MEDIUM, color: '#F5A623' },
                    { label: 'UNVERIFIED', count: sev.UNVERIFIED, color: '#64748B' },
                  ];
                  let offset = 0;
                  const arcs = [];
                  const circum = 238.76;
                  for (const item of items) {
                    const len = (item.count / total) * circum;
                    if (len > 0) {
                      arcs.push({ ...item, len, offset, label: item.label });
                    }
                    offset += len;
                  }
                  return arcs.map((a) =>
                    a.len >= 1 ? (
                      <circle
                        key={a.label}
                        cx="50" cy="50" r="38"
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
                <span className="text-[20px] font-bold text-[#1A1C21]">{stats.events_total}</span>
              </div>
            </div>

            <div className="text-[11px] space-y-1.5 text-[#5A626F]">
              {[
                { label: 'CRITICAL', count: stats.severity.CRITICAL, color: '#BD271E' },
                { label: 'HIGH', count: stats.severity.HIGH, color: '#D97706' },
                { label: 'MEDIUM', count: stats.severity.MEDIUM, color: '#F5A623' },
                { label: 'UNVERIFIED', count: stats.severity.UNVERIFIED, color: '#64748B' },
              ].map((s) =>
                s.count > 0 ? (
                  <div key={s.label} className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: s.color }} />
                    <span>{s.label}</span>
                    <span className="font-semibold">{s.count}</span>
                  </div>
                ) : null
              )}
            </div>
          </div>
        </ExpandableCard>

        {/* Card 2: Top paths (live dari event) */}
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
                <span className="text-[20px] font-bold text-[#1A1C21]">{topPaths.reduce((s, [, n]) => s + n, 0)}</span>
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
                    <span className="truncate max-w-[160px] font-mono" title={path}>{path.split('/').pop()}</span>
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

        {/* Card 4: Alerts evolution (histogram per hari dari ts event asli) */}
        <ExpandableCard title="Alerts evolution - 14 hari">

          <div className="flex items-center justify-between gap-4 h-56">
            <div className="flex-1 h-full flex flex-col justify-end">
              <div className="h-44 flex items-end justify-between gap-1 border-b border-[#D3DAE6] pb-1">
                {dailyHits.map((d) => (
                  <div key={d.label} className="flex-1 flex flex-col justify-end items-center h-full" title={`${d.label}: ${d.count} event`}>
                    <div
                      style={{ height: `${Math.round((d.count / dailyMax) * 100)}%`, minHeight: d.count > 0 ? 4 : 0 }}
                      className="bg-[#006BB4] w-full"
                    ></div>
                  </div>
                ))}
              </div>
              <div className="flex justify-between text-[10px] text-[#8A94A6] mt-2">
                <span>{dailyHits[0]?.label}</span>
                <span>{dailyHits[6]?.label}</span>
                <span>{dailyHits[13]?.label}</span>
              </div>
            </div>

            <div className="w-24 text-[11px] space-y-1.5 text-[#5A626F] shrink-0 border-l border-[#EBEFF5] pl-3">
              {topAgents.slice(0, 4).map(([name], i) => (
                <div key={name} className="flex items-center gap-1.5">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: TOP_AGENT_COLORS[i % TOP_AGENT_COLORS.length] }}
                  ></span>
                  <span className="truncate" title={name}>{name}</span>
                </div>
              ))}
            </div>
          </div>
        </ExpandableCard>
      </div>
      </>
      )}

      {/* Security Alerts Data Table Card */}
      <ExpandableCard title="Security Alerts">

        <div className="overflow-x-auto border border-[#EBEFF5] rounded">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F] font-semibold select-none">
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-3">Time ↓</th>
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
                  <td colSpan={10} className="py-6 text-center text-[#8A94A6]">
                    {query || activeFilters.length
                      ? `tidak ada event cocok "${[query, ...activeFilters].filter(Boolean).join(' + ')}"`
                      : 'belum ada event — drop EICAR di folder yang diawasi agent'}
                  </td>
                </tr>
              )}
              {pagedAlerts.map((row) => {
                const isExpanded = expandedRow === row.id;
                return (
                  <React.Fragment key={row.id}>
                    <tr className="hover:bg-[#F8FAFC] transition-colors">
                      <td className="py-2 px-3 text-center">
                        <button
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
                      <td className="py-2 px-3 text-[#1A1C21] max-w-md truncate">{row.description}</td>
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
                          if (st) return <span className="text-[11px] text-[#5A626F]">{st}</span>;
                          const dom = row.rawUrl ? domainOf(row.rawUrl) : '';
                          return (
                            <span className="inline-flex gap-1.5">
                              {row.rawPath && (
                                <button
                                  onClick={() => queueCommand(row.id, row.agentId, 'quarantine', row.rawPath)}
                                  title={`Karantina ${row.rawPath} di agent ${row.agentId}`}
                                  className="text-[11px] font-medium text-[#BD271E] border border-[#F5C2C0] bg-[#FDF3F2] hover:bg-[#FDE8E8] px-1.5 py-0.5 rounded"
                                >
                                  Karantina
                                </button>
                              )}
                              {dom && (
                                <button
                                  onClick={() => queueCommand(row.id, row.agentId, 'sinkhole', dom)}
                                  title={`Sinkhole ${dom} di agent ${row.agentId}`}
                                  className="text-[11px] font-medium text-[#B25E09] border border-[#F5D9A8] bg-[#FEF6E8] hover:bg-[#FDEFD4] px-1.5 py-0.5 rounded"
                                >
                                  Blokir
                                </button>
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
                            <div><strong>mitre.technique:</strong> &quot;{row.techniques}&quot;</div>
                            <div><strong>mitre.tactic:</strong> &quot;{row.tactics}&quot;</div>
                            <div><strong>location:</strong> &quot;wazuh-alerts&quot;</div>
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

        {/* Pagination bar */}
        <div className="flex items-center justify-between mt-3 text-[12px] text-[#5A626F]">
          <div className="flex items-center gap-2">
            <span>Rows per page:</span>
            <select
              value={rowsPerPage}
              onChange={(e) => {
                setRowsPerPage(Number(e.target.value));
                setPage(0);
              }}
              className="border border-[#D3DAE6] rounded px-1.5 py-0.5 bg-white text-[#1A1C21] outline-none"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
            <span>
              {visibleAlerts.length === 0
                ? '0'
                : `${safePage * rowsPerPage + 1}-${Math.min(safePage * rowsPerPage + rowsPerPage, visibleAlerts.length)}`}{' '}
              dari {visibleAlerts.length}
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={safePage === 0}
              className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] disabled:opacity-40 disabled:hover:bg-transparent"
              aria-label="Halaman sebelumnya"
            >
              ‹
            </button>
            <span className="font-semibold text-[#006BB4] px-1">
              {safePage + 1} / {pageCount}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              disabled={safePage >= pageCount - 1}
              className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] disabled:opacity-40 disabled:hover:bg-transparent"
              aria-label="Halaman berikut"
            >
              ›
            </button>
          </div>
        </div>
      </ExpandableCard>
    </div>
  );
}
