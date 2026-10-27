'use client';

import React, { useMemo } from 'react';
import {
  ShieldAlert,
  FileCheck2,
  ShieldCheck,
  Box,
  Server,
  HeartPulse,
  Network,
  SearchCheck,
  Workflow,
  Bot,
  ArrowUpRight,
} from 'lucide-react';

import type { FleetAgent, FleetHealth, FleetStats } from '@/lib/fleet';

interface ModulesHubProps {
  onNavigate: (
    moduleKey: string,
    options?: {
      severity?: string[];
      agentId?: string;
      tab?: 'dashboard' | 'events';
    }
  ) => void;
  /** Ringkasan fleet dari /api/fleet (live). */
  stats: FleetStats;
  agents: FleetAgent[];
  health?: FleetHealth;
}

interface ModuleItem {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: React.ReactNode;
  extra?: React.ReactNode;
}

interface SectionItem {
  title: string;
  wide?: boolean;
  modules: ModuleItem[];
}

export const ModulesHub = React.memo(function ModulesHub({
  onNavigate,
  stats,
  agents,
  health,
}: ModulesHubProps) {
  const linux = useMemo(
    () => agents.filter((a) => (a.os || '').toLowerCase().includes('linux')).length,
    [agents]
  );
  const windows = useMemo(
    () => agents.filter((a) => (a.os || '').toLowerCase().includes('windows')).length,
    [agents]
  );
  const mac = useMemo(
    () =>
      agents.filter((a) => {
        const s = (a.os || '').toLowerCase();
        return s.includes('mac') || s.includes('darwin');
      }).length,
    [agents]
  );
  const stackOk = useMemo(
    () => [health?.n8n, health?.gemini, health?.wazuh_api].filter(Boolean).length,
    [health]
  );

  const sections: SectionItem[] = useMemo(
    () => [
      {
        title: 'SECURITY INFORMATION MANAGEMENT',
        modules: [
          {
            id: 'security-events',
            title: 'Security events',
            description:
              'Browse and analyze security alerts, identifying threats and anomalies across your environment.',
            icon: ShieldAlert,
          },
          {
            id: 'integrity-monitoring',
            title: 'Integrity monitoring',
            description:
              'Real-time file integrity monitoring (FIM), tracking changes to permissions, ownership, and hashes.',
            icon: FileCheck2,
          },
        ],
      },
      {
        title: 'THREAT DETECTION AND RESPONSE',
        modules: [
          {
            id: 'threat-intel',
            title: 'Threat Intel',
            description:
              'Multi-engine verdicts (VirusTotal, MalwareBazaar, MISP, OTX) for suspicious artifacts via n8n.',
            icon: Box,
          },
          {
            id: 'mitre',
            title: 'MITRE ATT&CK',
            description:
              'Playbook mappings across tactics and techniques with automated response pipelines.',
            icon: ShieldCheck,
          },
        ],
      },
      {
        title: 'OPERATIONS',
        wide: true,
        modules: [
          {
            id: 'scan-on-demand',
            title: 'Scan on-demand',
            description:
              'Trigger folder hashing directly on Rust agents to detect unknown or modified binaries.',
            icon: SearchCheck,
          },
          {
            id: 'playbook-runs',
            title: 'Active playbooks',
            description:
              'Automated response workflows in n8n orchestrating containment, enrichment, and triage.',
            icon: Workflow,
          },
          {
            id: 'ai-triage',
            title: 'AI investigation',
            description:
              'Gemini LLM reasoning pipeline providing contextual analysis and attack explanations.',
            icon: Bot,
          },
        ],
      },
      {
        title: 'FLEET OVERVIEW',
        wide: true,
        modules: [
          {
            id: 'agents',
            title: 'Fleet inventory',
            description: `${stats.active}/${stats.total} online (Linux ${linux}, Windows ${windows}${mac > 0 ? `, macOS ${mac}` : ''}, ${stats.rust} endpoints).`,
            icon: Server,
            extra: (
              <div className="mt-2.5">
                <div className="h-1.5 w-full bg-[#EAEFF5] rounded-full overflow-hidden flex">
                  <div
                    className="bg-[#00A389] h-full transition-all"
                    style={{
                      width: `${stats.total > 0 ? (stats.active / stats.total) * 100 : 0}%`,
                    }}
                    title={`${stats.active} active`}
                  />
                  <div
                    className="bg-[#BD271E] h-full transition-all"
                    style={{
                      width: `${stats.total > 0 ? (stats.disconnected / stats.total) * 100 : 0}%`,
                    }}
                    title={`${stats.disconnected} disconnected`}
                  />
                </div>
              </div>
            ),
          },
          {
            id: 'settings',
            title: 'Stack health',
            description: `${stackOk}/3 services online (n8n, Gemini AI, Wazuh API). Inspect connection status and endpoints.`,
            icon: HeartPulse,
            badge: (
              <span
                className={`inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-full ${
                  stackOk === 3
                    ? 'bg-[#E6F6F4] text-[#00A389]'
                    : stackOk > 0
                    ? 'bg-[#FFF8E6] text-[#D97706]'
                    : 'bg-[#FDF3F2] text-[#BD271E]'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    stackOk === 3
                      ? 'bg-[#00A389]'
                      : stackOk > 0
                      ? 'bg-[#D97706]'
                      : 'bg-[#BD271E]'
                  }`}
                />
                {stackOk === 3 ? 'Healthy' : `${stackOk}/3 Partial`}
              </span>
            ),
          },
          {
            id: 'network-map',
            title: 'Network map',
            description: `Hub-and-spoke topology of ${stats.active}/${stats.total} active agents. Interactive node exploration.`,
            icon: Network,
          },
        ],
      },
    ],
    [stats, linux, windows, mac, stackOk]
  );

  return (
    <div className="space-y-6">
      {/* Agent KPI Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 px-1 rounded transition-colors group"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#006BB4] transition-colors">
            Total agents
          </div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">
            {stats.total}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">
            {stats.rust} Rust · {stats.wazuh} Wazuh
          </div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 px-1 rounded transition-colors group"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#00A389] transition-colors">
            Active agents
          </div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">
            {stats.active}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">
            {stats.total > 0 ? Math.round((stats.active / stats.total) * 100) : 0}% operational
          </div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 px-1 rounded transition-colors group"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#BD271E] transition-colors">
            Disconnected agents
          </div>
          <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">
            {stats.disconnected}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">
            {stats.disconnected > 0 && stats.total > 0
              ? `${Math.round((stats.disconnected / stats.total) * 100)}% offline`
              : 'All connected'}
          </div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 px-1 rounded transition-colors group"
          onClick={() => onNavigate('security-events')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium group-hover:text-[#006BB4] transition-colors">
            Threat events
          </div>
          <div className="text-[32px] font-semibold text-[#1A1C21] leading-tight mt-1">
            {stats.events_total.toLocaleString('en-US')}
          </div>
          {/* Clean Severity Numbers */}
          <div className="flex items-center justify-center gap-2 mt-1 text-[11px] text-[#5A626F]">
            <span
              onClick={(e) => {
                e.stopPropagation();
                onNavigate('security-events', { severity: ['CRITICAL'] });
              }}
              className="hover:underline cursor-pointer"
              title="Filter Critical events"
            >
              <span className="font-semibold text-[#BD271E]">{stats.severity?.CRITICAL || 0}</span> critical
            </span>
            <span className="text-[#D3DAE6]">·</span>
            <span
              onClick={(e) => {
                e.stopPropagation();
                onNavigate('security-events', { severity: ['HIGH'] });
              }}
              className="hover:underline cursor-pointer"
              title="Filter High events"
            >
              <span className="font-semibold text-[#D97706]">{stats.severity?.HIGH || 0}</span> high
            </span>
          </div>
        </div>
      </div>

      {/* 2x2 / Wide Category Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
        {sections.map((section) => (
          <div
            key={section.title}
            className={`relative border border-[#D3DAE6] rounded bg-white p-5 pt-7 flex flex-col ${
              section.wide ? 'lg:col-span-2' : ''
            }`}
          >
            {/* Pill Header Badge */}
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white border border-[#D3DAE6] px-4 py-0.5 rounded-full text-[11px] font-bold tracking-wider text-[#1A1C21] uppercase whitespace-nowrap shadow-xs">
              {section.title}
            </div>

            {/* Modules Grid */}
            <div
              className={`grid gap-3.5 flex-1 auto-rows-fr ${
                section.wide ? 'grid-cols-1 sm:grid-cols-3' : 'grid-cols-1 sm:grid-cols-2'
              }`}
            >
              {section.modules.map((mod) => {
                const Icon = mod.icon;
                return (
                  <div
                    key={mod.id}
                    onClick={() => {
                      onNavigate(mod.id);
                    }}
                    className="relative border border-[#D3DAE6] rounded p-3.5 flex items-start gap-3 bg-white transition-all shadow-xs hover:border-[#006BB4] hover:bg-[#F8FAFC] cursor-pointer group"
                  >
                    <div className="mt-0.5 p-2 rounded bg-[#F5F7FA] text-[#006BB4] shrink-0 group-hover:bg-[#EBF5FB] group-hover:text-[#005593] transition-colors">
                      <Icon className="w-5 h-5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-1">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span className="text-[13px] font-semibold text-[#1A1C21] leading-snug group-hover:text-[#006BB4] transition-colors truncate">
                            {mod.title}
                          </span>
                          {mod.badge}
                        </div>
                        <ArrowUpRight className="w-3.5 h-3.5 text-[#8A94A6] opacity-0 group-hover:opacity-100 group-hover:text-[#006BB4] transition-all transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5 shrink-0" />
                      </div>
                      <div className="text-[11px] text-[#5A626F] mt-1 line-clamp-3 leading-relaxed">
                        {mod.description}
                      </div>
                      {mod.extra}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
});
