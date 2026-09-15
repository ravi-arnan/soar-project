'use client';

import React, { useState } from 'react';
import {
  Maximize2,
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

export function AgentDetailView({
  agentId = '004',
  agent,
  events = [],
  onNavigateTab,
}: AgentDetailViewProps) {
  const [activeTab, setActiveTab] = useState<string | null>(null);

  const status = agentStatus(agent?.status || 'active');
  const agentEvents = events.filter((e) => e.agent_id === agentId).slice(0, 4);

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

        <button className="flex items-center gap-1 text-[#006BB4] hover:underline border border-[#D3DAE6] px-2.5 py-1 rounded bg-[#F8FAFC]">
          <span>Last 7 days</span>
          <ChevronDown className="w-3 h-3" />
        </button>
      </div>

      {/* 3 Columns Top Row: MITRE, Compliance, FIM */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Card 1: MITRE Top Tactics */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3 border-b border-[#EBEFF5] pb-2">
            <div className="text-[13px] font-semibold text-[#1A1C21]">MITRE</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

          <div className="text-[12px] font-semibold text-[#5A626F] mb-2">Top Tactics</div>
          <div className="space-y-2.5 text-[12px]">
            <div className="flex items-center justify-between">
              <span className="text-[#1A1C21]">Lateral Movement</span>
              <span className="font-semibold bg-[#F0F4F8] px-2 py-0.5 rounded text-[#5A626F]">207</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#1A1C21]">Credential Access</span>
              <span className="font-semibold bg-[#F0F4F8] px-2 py-0.5 rounded text-[#5A626F]">84</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#1A1C21]">Collection</span>
              <span className="font-semibold bg-[#F0F4F8] px-2 py-0.5 rounded text-[#5A626F]">57</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#1A1C21]">Impact</span>
              <span className="font-semibold bg-[#F0F4F8] px-2 py-0.5 rounded text-[#5A626F]">57</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#1A1C21]">Initial Access</span>
              <span className="font-semibold bg-[#F0F4F8] px-2 py-0.5 rounded text-[#5A626F]">32</span>
            </div>
          </div>
        </div>

        {/* Card 2: Compliance Donut */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3 border-b border-[#EBEFF5] pb-2">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Compliance</div>
            <div className="flex items-center gap-1 text-[12px] text-[#5A626F]">
              <span>PCI DSS</span>
              <ChevronDown className="w-3 h-3" />
            </div>
          </div>

          <div className="flex items-center justify-center gap-4 h-48">
            <div className="relative w-32 h-32 flex items-center justify-center">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <circle cx="50" cy="50" r="38" fill="none" stroke="#00A389" strokeWidth="16" strokeDasharray="90 150" strokeDashoffset="0" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#006BB4" strokeWidth="16" strokeDasharray="60 180" strokeDashoffset="-90" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#E2557B" strokeWidth="16" strokeDasharray="40 200" strokeDashoffset="-150" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#8E44AD" strokeWidth="16" strokeDasharray="30 210" strokeDashoffset="-190" />
              </svg>
            </div>

            <div className="text-[11px] space-y-1.5 text-[#5A626F]">
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#00A389]"></span><span>11.4 (542)</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#006BB4]"></span><span>2.2 (405)</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#E2557B]"></span><span>10.2.4 (320)</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#8E44AD]"></span><span>10.2.5 (216)</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#E67E22]"></span><span>6.5 (207)</span></div>
            </div>
          </div>
        </div>

        {/* Card 3: FIM: Recent events */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3 border-b border-[#EBEFF5] pb-2">
            <div className="text-[13px] font-semibold text-[#1A1C21]">FIM: Recent events</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

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
        </div>
      </div>

      {/* Bottom Row: Events Count Evolution & SCA Scan */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Card 4: Events Count Evolution */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3 border-b border-[#EBEFF5] pb-2">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Events count evolution</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

          <div className="h-44 flex flex-col justify-end">
            <svg viewBox="0 0 400 120" className="w-full h-full overflow-visible">
              <path
                d="M0,90 L30,85 L60,88 L90,95 L120,85 L150,90 L180,88 L210,92 L240,85 L270,88 L300,90 L330,85 L360,20 L380,110 L400,90"
                fill="none"
                stroke="#00A389"
                strokeWidth="2.5"
              />
              <line x1="0" y1="110" x2="400" y2="110" stroke="#D3DAE6" strokeWidth="1" />
            </svg>
            <div className="flex justify-between text-[10px] text-[#8A94A6] mt-2">
              <span>2026-01-18 00:00</span>
              <span>2026-01-20 00:00</span>
              <span>2026-01-22 00:00</span>
              <span>2026-01-24 00:00</span>
            </div>
          </div>
        </div>

        {/* Card 5: SCA Last scan */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3 border-b border-[#EBEFF5] pb-2">
            <div className="text-[13px] font-semibold text-[#1A1C21]">SCA: Last scan</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-[13px] font-semibold text-[#006BB4]">CIS benchmark for Ubuntu Linux 18.04 LTS</span>
              <span className="bg-[#00A389] text-white text-[10px] font-semibold px-2 py-0.5 rounded">
                cis_ubuntu18-04
              </span>
            </div>

            <p className="text-[11px] text-[#5A626F] leading-relaxed">
              This document provides prescriptive guidance for establishing a secure configuration posture for Ubuntu Linux 18.04 LTS.
            </p>

            <div className="grid grid-cols-4 gap-2 text-center py-2 bg-[#F8FAFC] border border-[#EBEFF5] rounded">
              <div>
                <div className="text-[11px] text-[#5A626F]">Pass</div>
                <div className="text-[20px] font-semibold text-[#00A389]">34</div>
              </div>
              <div>
                <div className="text-[11px] text-[#5A626F]">Fail</div>
                <div className="text-[20px] font-semibold text-[#BD271E]">82</div>
              </div>
              <div>
                <div className="text-[11px] text-[#5A626F]">Total checks</div>
                <div className="text-[20px] font-semibold text-[#1A1C21]">198</div>
              </div>
              <div>
                <div className="text-[11px] text-[#5A626F]">Score</div>
                <div className="text-[20px] font-semibold text-[#1A1C21]">29%</div>
              </div>
            </div>

            <div className="flex justify-between items-center text-[11px] text-[#8A94A6]">
              <span>Start time: Jan 24, 2026 @ 08:47:02.000</span>
              <span>Duration: &lt; 1s</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
