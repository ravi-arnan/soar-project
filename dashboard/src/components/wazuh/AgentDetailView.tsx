'use client';

import React, { useEffect, useState } from 'react';
import {
  Calendar,
  ChevronDown,
  Database,
  Sliders,
  Settings,
  ShieldAlert,
  Clock,
  ExternalLink,
} from 'lucide-react';

import { agentStatus, formatWazuhTime, formatClock, severityLevel } from '@/lib/fleet';
import { ExpandableCard } from './ExpandableCard';
import type { FleetAgent, FleetEvent } from '@/lib/fleet';

interface AgentDetailViewProps {
  agentId?: string;
  /** Agent terpilih dari /api/fleet. */
  agent?: FleetAgent;
  /** Event live dari /api/events (dipakai untuk FIM: Recent events). */
  events?: FleetEvent[];
  onNavigateTab?: (tab: string) => void;
}

const STATUS_DOT: Record<string, string> = {
  active: '#00A389',
  disconnected: '#BD271E',
  never_connected: '#98A2B3',
};

interface MetricPoint {
  ts: string;
  cpu_pct: number;
  ram_used: number;
  ram_total: number;
}

/** Grafik garis resource (CPU% + RAM GB) dari /api/metrics, SVG native. */
function ResourceChart({ agentId }: { agentId: string }) {
  const [points, setPoints] = useState<MetricPoint[]>([]);
  useEffect(() => {
    let alive = true;
    fetch(`/api/metrics?agent_id=${encodeURIComponent(agentId)}`)
      .then((r) => r.json())
      .then((d) => {
        if (alive) setPoints(d.points || []);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [agentId]);

  if (!points.length) {
    return (
      <div className="text-[12px] text-[#8A94A6] py-6 text-center">
        Belum ada data resource — menunggu heartbeat agent (60 dtk).
      </div>
    );
  }

  const W = 400;
  const H = 120;
  const maxCpu = Math.max(10, ...points.map((p) => p.cpu_pct));
  const maxRam = Math.max(1, ...points.map((p) => p.ram_total || p.ram_used));
  const n = points.length;
  const x = (i: number) => (n === 1 ? W / 2 : (i / (n - 1)) * W);
  const cpuLine = points.map((p, i) => `${x(i).toFixed(1)},${(H - (p.cpu_pct / maxCpu) * (H - 10) - 5).toFixed(1)}`).join(' ');
  const ramLine = points.map((p, i) => `${x(i).toFixed(1)},${(H - (p.ram_used / maxRam) * (H - 10) - 5).toFixed(1)}`).join(' ');
  const last = points[n - 1];

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-28">
        <line x1="0" y1={H - 1} x2={W} y2={H - 1} stroke="#D3DAE6" strokeWidth="1" />
        <polyline points={cpuLine} fill="none" stroke="#006BB4" strokeWidth="1.5" />
        <polyline points={ramLine} fill="none" stroke="#00A389" strokeWidth="1.5" />
      </svg>
      <div className="flex items-center gap-4 mt-1 text-[11px] text-[#5A626F]">
        <span className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-[#006BB4]"></span>
          CPU {last.cpu_pct.toFixed(1)}%
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-[#00A389]"></span>
          RAM {last.ram_used.toFixed(1)}/{last.ram_total.toFixed(1)} GB
        </span>
        <span className="ml-auto">{n} titik</span>
      </div>
    </div>
  );
}

export function AgentDetailView({
  agentId = '004',
  agent,
  events = [],
  onNavigateTab,
}: AgentDetailViewProps) {
  const [activeTab, setActiveTab] = useState<string | null>(null);

  const status = agentStatus(agent?.status || 'active');
  const allAgentEvents = events.filter((e) => e.agent_id === agentId);
  const agentEvents = allAgentEvents.slice(0, 4);

  // Severity breakdown agent ini (live dari event).
  const sevCounts = [
    { label: 'CRITICAL', count: 0, color: '#BD271E' },
    { label: 'HIGH', count: 0, color: '#D97706' },
    { label: 'MEDIUM', count: 0, color: '#F5A623' },
    { label: 'UNVERIFIED', count: 0, color: '#64748B' },
    { label: 'INFO', count: 0, color: '#006BB4' },
  ];
  allAgentEvents.forEach((e) => {
    const s = (e.severity || 'INFO').toUpperCase();
    const row = sevCounts.find((c) => c.label === s) || sevCounts[4];
    row.count += 1;
  });
  const sevMax = Math.max(1, ...sevCounts.map((c) => c.count));

  // Histogram event agent ini per hari, 14 hari terakhir (live dari ts).
  const agentDaily = (() => {
    const days: { label: string; count: number }[] = [];
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    for (let i = 13; i >= 0; i--) {
      const d = new Date(today - i * 86400000);
      days.push({ label: `${d.getDate()}/${d.getMonth() + 1}`, count: 0 });
    }
    allAgentEvents.forEach((e) => {
      const t = new Date(e.ts).getTime();
      if (Number.isNaN(t)) return;
      const day = new Date(new Date(t).getFullYear(), new Date(t).getMonth(), new Date(t).getDate()).getTime();
      const idx = 13 - Math.round((today - day) / 86400000);
      if (idx >= 0 && idx < 14) days[idx].count += 1;
    });
    return days;
  })();
  const agentDailyMax = Math.max(1, ...agentDaily.map((d) => d.count));

  const tabs = [
    agent?.name || 'Ubuntu',
    'Security events',
    'Integrity monitoring',
    'SCA',
    'System Auditing',
    'Threat Intel',
    'MITRE ATT&CK',
  ];
  const currentTab = activeTab ?? tabs[0];

  return (
    <div className="space-y-4">
      {/* Top Sub-tabs & Actions */}
      <div className="flex flex-wrap items-center justify-between border-b border-[#D3DAE6] pb-1 gap-2">
        <div className="flex items-center gap-5 text-[13px] overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => {
                setActiveTab(tab);
                onNavigateTab?.(tab);
              }}
              className={`pb-2 -mb-1 whitespace-nowrap font-medium transition-colors ${
                currentTab === tab
                  ? 'border-b-2 border-[#006BB4] text-[#006BB4]'
                  : 'text-[#5A626F] hover:text-[#1A1C21]'
              }`}
            >
              {tab}
            </button>
          ))}
          <button className="flex items-center gap-1 text-[#5A626F] hover:text-[#1A1C21] pb-2 -mb-1 text-[13px]">
            <span>More...</span>
            <ChevronDown className="w-3 h-3" />
          </button>
        </div>

        <div className="flex items-center gap-4 text-[12px] text-[#006BB4]">
          <button className="flex items-center gap-1 hover:underline font-medium">
            <Database className="w-3.5 h-3.5" />
            <span>Inventory data</span>
          </button>
          <button className="flex items-center gap-1 hover:underline font-medium">
            <Sliders className="w-3.5 h-3.5" />
            <span>Stats</span>
          </button>
          <button className="flex items-center gap-1 hover:underline font-medium">
            <Settings className="w-3.5 h-3.5" />
            <span>Configuration</span>
          </button>
        </div>
      </div>

      {/* Agent Metadata Strip */}
      <div className="bg-white border border-[#D3DAE6] rounded p-4 flex flex-wrap items-center justify-between gap-4 text-[12px]">
        <div>
          <div className="text-[#8A94A6] text-[11px]">ID</div>
          <div className="font-semibold text-[#1A1C21] mt-0.5">{agent?.id || agentId}</div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">Status</div>
          <div
            className="flex items-center gap-1.5 font-medium mt-0.5"
            style={{ color: STATUS_DOT[status] }}
          >
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: STATUS_DOT[status] }}></span>
            <span>{status.replace('_', ' ')}</span>
          </div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">IP</div>
          <div className="font-mono text-[#1A1C21] mt-0.5">{agent?.ip || '-'}</div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">Version</div>
          <div className="font-mono text-[#1A1C21] mt-0.5">{agent?.version || '-'}</div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">Groups</div>
          <div className="flex gap-1 mt-0.5">
            <span className="bg-[#F0F4F8] border border-[#D3DAE6] px-1.5 py-0.5 rounded text-[10px] text-[#5A626F]">default</span>
            <span className="bg-[#F0F4F8] border border-[#D3DAE6] px-1.5 py-0.5 rounded text-[10px] text-[#5A626F]">
              {agent?.type === 'rust' ? 'soar-agent' : 'wazuh'}
            </span>
          </div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">Operating system</div>
          <div className="font-medium text-[#1A1C21] mt-0.5">
            {agent?.os && agent.os !== 'unknown' ? agent.os : '-'}
          </div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">Cluster node</div>
          <div className="text-[#1A1C21] mt-0.5">-</div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">Registration date</div>
          <div className="text-[#5A626F] mt-0.5">-</div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">Last keep alive</div>
          <div className="text-[#5A626F] mt-0.5">{formatWazuhTime(agent?.lastKeepAlive || '-')}</div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">CPU</div>
          <div className="font-mono text-[#1A1C21] mt-0.5">
            {typeof agent?.cpu_pct === 'number' && agent.cpu_pct > 0
              ? `${agent.cpu_pct.toFixed(1)}%`
              : '-'}
          </div>
        </div>

        <div>
          <div className="text-[#8A94A6] text-[11px]">RAM used / total</div>
          <div className="font-mono text-[#1A1C21] mt-0.5">
            {agent?.ram_gb?.total
              ? `${(agent.ram_gb.used || 0).toFixed(1)} / ${agent.ram_gb.total.toFixed(1)} GB`
              : '-'}
          </div>
        </div>

        <button className="flex items-center gap-1 text-[#006BB4] hover:underline border border-[#D3DAE6] px-2.5 py-1 rounded bg-[#F8FAFC]">
          <span>Last 7 days</span>
          <ChevronDown className="w-3 h-3" />
        </button>
      </div>

      {/* Top Row: Severity + FIM (live dari event agent ini) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Card 1: Severity breakdown */}
        <ExpandableCard title="Severity">

          <div className="text-[12px] font-semibold text-[#5A626F] mb-2">
            {allAgentEvents.length} event agent ini
          </div>
          <div className="space-y-2.5 text-[12px]">
            {sevCounts.map((s) => (
              <div key={s.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="flex items-center gap-2 text-[#1A1C21]">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: s.color }}></span>
                    {s.label}
                  </span>
                  <span className="font-semibold bg-[#F0F4F8] px-2 py-0.5 rounded text-[#5A626F]">{s.count}</span>
                </div>
                <div className="h-1.5 bg-[#F0F4F8] rounded">
                  <div
                    className="h-1.5 rounded"
                    style={{ width: `${Math.round((s.count / sevMax) * 100)}%`, backgroundColor: s.color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </ExpandableCard>
        <ExpandableCard title="FIM: Recent events">

          <div className="overflow-x-auto text-[11px]">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[#D3DAE6] text-[#8A94A6]">
                  <th className="pb-1">Time ↓</th>
                  <th className="pb-1">Path</th>
                  <th className="pb-1">Action</th>
                  <th className="pb-1 text-right">Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EBEFF5]">
                {agentEvents.length ? (
                  agentEvents.map((e, i) => {
                    const level = severityLevel(e.severity);
                    return (
                      <tr key={`${e.ts}-${i}`}>
                        <td className="py-1.5 text-[#5A626F]">{formatClock(e.ts)}</td>
                        <td
                          className="py-1.5 text-[#006BB4] font-mono truncate max-w-[120px]"
                          title={e.path}
                        >
                          {(e.path || '-').split('/').pop()}
                        </td>
                        <td className="py-1.5 text-[#1A1C21]">{e.status || '-'}</td>
                        <td
                          className={`py-1.5 text-right font-medium ${
                            level >= 7 ? 'text-[#BD271E]' : 'text-[#006BB4]'
                          }`}
                        >
                          {level}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={4} className="py-4 text-center text-[#8A94A6]">
                      belum ada event untuk agent ini
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </ExpandableCard>
      </div>

      {/* Bottom Row: Resource usage & Events Count Evolution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Card: Resource usage (live dari heartbeat agent) */}
        <ExpandableCard title="Resource usage">
          <ResourceChart agentId={agentId} />
        </ExpandableCard>

        {/* Card: Events evolution (histogram per hari dari ts asli) */}
        <ExpandableCard title="Events count evolution">

          <div className="h-44 flex flex-col justify-end">
            <div className="flex-1 flex items-end justify-between gap-1 border-b border-[#D3DAE6] pb-1">
              {agentDaily.map((d) => (
                <div key={d.label} className="flex-1 flex flex-col justify-end items-center h-full" title={`${d.label}: ${d.count} event`}>
                  <div
                    style={{ height: `${Math.round((d.count / agentDailyMax) * 100)}%`, minHeight: d.count > 0 ? 4 : 0 }}
                    className="bg-[#00A389] w-full"
                  ></div>
                </div>
              ))}
            </div>
            <div className="flex justify-between text-[10px] text-[#8A94A6] mt-2">
              <span>{agentDaily[0]?.label}</span>
              <span>{agentDaily[6]?.label}</span>
              <span>{agentDaily[13]?.label}</span>
            </div>
          </div>
        </ExpandableCard>
      </div>
    </div>
  );
}
