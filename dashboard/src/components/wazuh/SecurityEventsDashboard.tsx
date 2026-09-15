'use client';

import React, { useMemo, useState } from 'react';
import {
  Radio,
  FileText,
  Maximize2,
  ChevronRight,
  ChevronDown,
  Info,
  List,
} from 'lucide-react';
import { WazuhFilterBar } from './WazuhFilterBar';
import { formatWazuhTime, severityLevel } from '@/lib/fleet';
import type { FleetEvent, FleetStats } from '@/lib/fleet';

interface SecurityEventsDashboardProps {
  onSelectAgent?: (agentId: string) => void;
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
  events,
  stats,
  onRefresh,
}: SecurityEventsDashboardProps) {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'events'>('dashboard');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [query, setQuery] = useState('');

  // Event live -> baris tabel ala Wazuh. `level` mengikuti bucket severity fleet
  // (CRITICAL=12, HIGH=8, MEDIUM=5, UNVERIFIED=4, INFO=3).
  const alertsData = useMemo(
    () =>
      events.map((e, i) => ({
        id: i + 1,
        time: formatWazuhTime(e.ts),
        agentId: e.agent_id || '-',
        agentName: e.agent || '-',
        techniques: '-',
        tactics: '-',
        description: e.ai ? `${e.path || '-'} — ${e.ai}` : e.path || e.status || '-',
        level: severityLevel(e.severity),
        ruleId: (e.severity || 'INFO').toUpperCase(),
      })),
    [events]
  );

  // Filter search dari WazuhFilterBar: cocokkan ke deskripsi / agent / rule.
  const visibleAlerts = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return alertsData;
    return alertsData.filter((r) =>
      `${r.description} ${r.agentName} ${r.agentId} ${r.ruleId}`.toLowerCase().includes(q)
    );
  }, [alertsData, query]);

  // Top 5 agent menurut jumlah event.
  const topAgents = useMemo(() => {
    const counts = new Map<string, number>();
    events.forEach((e) => {
      const key = e.agent || '-';
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [events]);

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
          <button className="flex items-center gap-1.5 text-[#006BB4] hover:underline font-medium">
            <Radio className="w-3.5 h-3.5" />
            <span>Explore agent</span>
          </button>
          <button className="flex items-center gap-1.5 text-[#006BB4] hover:underline font-medium">
            <FileText className="w-3.5 h-3.5" />
            <span>Generate report</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <WazuhFilterBar onRefresh={onRefresh} onSearch={setQuery} />

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
        {/* Card 1: Alert Level Evolution */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4 relative">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Alert level evolution</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6] cursor-pointer hover:text-[#1A1C21]" />
          </div>

          <div className="flex items-center justify-between gap-4">
            <div className="flex-1 h-56 flex flex-col justify-end">
              <svg viewBox="0 0 400 160" className="w-full h-full overflow-visible">
                <defs>
                  <linearGradient id="grad1" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stopColor="#006BB4" stopOpacity="0.8" />
                    <stop offset="100%" stopColor="#006BB4" stopOpacity="0.2" />
                  </linearGradient>
                  <linearGradient id="grad2" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stopColor="#BD271E" stopOpacity="0.8" />
                    <stop offset="100%" stopColor="#BD271E" stopOpacity="0.2" />
                  </linearGradient>
                </defs>
                <path
                  d="M0,130 Q40,110 80,120 T160,115 T240,125 T320,100 L380,30 L400,140 L0,140 Z"
                  fill="url(#grad1)"
                />
                <path
                  d="M0,140 Q40,130 80,135 T160,130 T240,135 T320,120 L380,60 L400,150 L0,150 Z"
                  fill="url(#grad2)"
                />
                <line x1="0" y1="150" x2="400" y2="150" stroke="#D3DAE6" strokeWidth="1" />
              </svg>
              <div className="flex justify-between text-[10px] text-[#8A94A6] mt-2">
                <span>2026-01-18 00:00</span>
                <span>2026-01-20 00:00</span>
                <span>2026-01-22 00:00</span>
                <span>2026-01-24 00:00</span>
              </div>
            </div>

            {/* Legend */}
            <div className="w-20 text-[11px] space-y-1 text-[#5A626F] shrink-0 border-l border-[#EBEFF5] pl-3">
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#BD271E]"></span><span>12+</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#D97706]"></span><span>8-11</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#F5A623]"></span><span>5-7</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#00A389]"></span><span>3-4</span></div>
            </div>
          </div>
        </div>

        {/* Card 2: Top MITRE ATT&CKS */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4 relative">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Top MITRE ATT&CKS</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6] cursor-pointer hover:text-[#1A1C21]" />
          </div>

          <div className="flex items-center justify-center gap-6 h-56">
            <div className="relative w-40 h-40 flex items-center justify-center">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <circle cx="50" cy="50" r="38" fill="none" stroke="#EBEFF5" strokeWidth="18" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#D9381E" strokeWidth="18" strokeDasharray="60 180" strokeDashoffset="0" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#00A389" strokeWidth="18" strokeDasharray="50 190" strokeDashoffset="-60" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#006BB4" strokeWidth="18" strokeDasharray="40 200" strokeDashoffset="-110" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#9B51E0" strokeWidth="18" strokeDasharray="30 210" strokeDashoffset="-150" />
              </svg>
            </div>

            <div className="text-[11px] space-y-1 text-[#5A626F] overflow-y-auto max-h-48 pr-2">
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#D9381E]"></span><span>Brute Force</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#00A389]"></span><span>Remove Services</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#006BB4]"></span><span>Email Collection</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#9B51E0]"></span><span>Valid Accounts</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#E2B93B]"></span><span>Sudo</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#27AE60]"></span><span>Endpoint Denial of Service</span></div>
            </div>
          </div>
        </div>

        {/* Card 3: Top 5 Agents */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4 relative">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Top 5 agents</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6] cursor-pointer hover:text-[#1A1C21]" />
          </div>

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
        </div>

        {/* Card 4: Alerts evolution - Top 5 agents */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4 relative">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Alerts evolution - Top 5 agents</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6] cursor-pointer hover:text-[#1A1C21]" />
          </div>

          <div className="flex items-center justify-between gap-4 h-56">
            <div className="flex-1 h-full flex flex-col justify-end">
              {/* Stacked bar visualization */}
              <div className="h-44 flex items-end justify-between gap-1 border-b border-[#D3DAE6] pb-1">
                {Array.from({ length: 24 }).map((_, i) => (
                  <div key={i} className="flex-1 flex flex-col justify-end h-full">
                    <div style={{ height: `${20 + (i % 5) * 12}%` }} className="bg-[#9B51E0] w-full"></div>
                    <div style={{ height: `${15 + (i % 3) * 8}%` }} className="bg-[#00A389] w-full"></div>
                    <div style={{ height: `${25 + (i % 4) * 10}%` }} className="bg-[#006BB4] w-full"></div>
                    <div style={{ height: `${10 + (i % 6) * 5}%` }} className="bg-[#D9381E] w-full"></div>
                  </div>
                ))}
              </div>
              <div className="flex justify-between text-[10px] text-[#8A94A6] mt-2">
                <span>2026-01-18 00:00</span>
                <span>2026-01-21 00:00</span>
                <span>2026-01-24 00:00</span>
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
        </div>
      </div>

      {/* Security Alerts Data Table Card */}
      <div className="bg-white border border-[#D3DAE6] rounded p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-[13px] font-semibold text-[#1A1C21]">Security Alerts</div>
          <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6] cursor-pointer hover:text-[#1A1C21]" />
        </div>

        <div className="overflow-x-auto border border-[#EBEFF5] rounded">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F] font-semibold select-none">
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-3">Time ↓</th>
                <th className="py-2.5 px-3">Agent</th>
                <th className="py-2.5 px-3">Agent name</th>
                <th className="py-2.5 px-3">Technique(s)</th>
                <th className="py-2.5 px-3">Tactic(s)</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3 text-center">Level</th>
                <th className="py-2.5 px-3 text-right">Rule ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEFF5]">
              {!visibleAlerts.length && (
                <tr>
                  <td colSpan={9} className="py-6 text-center text-[#8A94A6]">
                    {query
                      ? `tidak ada event cocok "${query}"`
                      : 'belum ada event — drop EICAR di folder yang diawasi agent'}
                  </td>
                </tr>
              )}
              {visibleAlerts.map((row) => {
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
                      <td className="py-2 px-3 text-[#006BB4] font-mono">
                        {row.techniques !== '-' ? (
                          <span className="hover:underline cursor-pointer">{row.techniques}</span>
                        ) : (
                          '-'
                        )}
                      </td>
                      <td className="py-2 px-3 text-[#5A626F] whitespace-nowrap">{row.tactics}</td>
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
                      <td className="py-2 px-3 text-right font-medium">
                        <span className="text-[#006BB4] hover:underline cursor-pointer">
                          {row.ruleId}
                        </span>
                      </td>
                    </tr>

                    {/* Expandable row with JSON details */}
                    {isExpanded && (
                      <tr className="bg-[#F8FAFC]">
                        <td colSpan={9} className="p-4">
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
            <select className="border border-[#D3DAE6] rounded px-1.5 py-0.5 bg-white text-[#1A1C21] outline-none">
              <option>10</option>
              <option>25</option>
              <option>50</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <button className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] text-[#8A94A6]">‹</button>
            <span className="font-semibold text-[#006BB4] px-1">1</span>
            <button className="px-1 hover:text-[#1A1C21]">2</button>
            <button className="px-1 hover:text-[#1A1C21]">3</button>
            <button className="px-1 hover:text-[#1A1C21]">4</button>
            <button className="px-1 hover:text-[#1A1C21]">5</button>
            <span>...</span>
            <button className="px-1 hover:text-[#1A1C21]">1000</button>
            <button className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] text-[#1A1C21]">›</button>
          </div>
        </div>
      </div>
    </div>
  );
}
