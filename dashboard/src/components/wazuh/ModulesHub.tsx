'use client';

import React, { useMemo } from 'react';
import { WuiIcon, type WuiIconType } from '../wui/WuiIcon';
import { WuiPanel } from '../wui/WuiPrimitives';

import type {
  FleetAgent,
  FleetHealth,
  FleetStats,
  HistorySource,
  PeriodPreset,
} from '@/lib/fleet';

interface ModulesHubProps {
  onNavigate: (
    moduleKey: string,
    options?: {
      severity?: string[];
      agentId?: string;
      tab?: 'dashboard' | 'events';
      period?: PeriodPreset;
      source?: HistorySource;
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
  icon: WuiIconType;
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
        title: 'Security information management',
        modules: [
          {
            id: 'security-events',
            title: 'Security events',
            description:
              'Browse and analyze security alerts, identifying threats and anomalies across your environment.',
            icon: 'securityAnalyticsApp',
          },
          {
            id: 'integrity-monitoring',
            title: 'Integrity monitoring',
            description:
              'Real-time file integrity monitoring (FIM), tracking changes to permissions, ownership, and hashes.',
            icon: 'sqlApp',
          },
        ],
      },
      {
        title: 'Threat detection and response',
        modules: [
          {
            id: 'threat-intel',
            title: 'Threat Intel',
            description:
              'Multi-engine verdicts (VirusTotal, MalwareBazaar, MISP, OTX) for suspicious artifacts via n8n.',
            icon: 'indexRollupApp',
          },
          {
            id: 'mitre',
            title: 'MITRE ATT&CK',
            description:
              'Playbook mappings across tactics and techniques with automated response pipelines.',
            icon: 'grokApp',
          },
        ],
      },
      {
        title: 'Operations',
        wide: true,
        modules: [
          {
            id: 'scan-on-demand',
            title: 'Scan on-demand',
            description:
              'Trigger folder hashing directly on Rust agents to detect unknown or modified binaries.',
            icon: 'search',
          },
          {
            id: 'playbook-runs',
            title: 'Active playbooks',
            description:
              'Automated response workflows in n8n orchestrating containment, enrichment, and triage.',
            icon: 'bolt',
          },
          {
            id: 'ai-triage',
            title: 'AI investigation',
            description:
              'Multi-provider LLM reasoning pipeline providing contextual analysis and attack explanations.',
            icon: 'machineLearningApp',
          },
        ],
      },
      {
        title: 'Fleet overview',
        wide: true,
        modules: [
          {
            id: 'agents',
            title: 'Fleet inventory',
            description: `${stats.active}/${stats.total} online (Linux ${linux}, Windows ${windows}${mac > 0 ? `, macOS ${mac}` : ''}, ${stats.rust} endpoints).`,
            icon: 'spacesApp',
            extra: (
              <div className="mt-2.5">
                <div className="h-1 w-full bg-[#E9EDF3] rounded-[2px] overflow-hidden flex">
                  <div
                    className="bg-[#017D73] h-full transition-[width]"
                    style={{
                      width: `${stats.total > 0 ? (stats.active / stats.total) * 100 : 0}%`,
                    }}
                    title={`${stats.active} active`}
                  />
                  <div
                    className="bg-[#BD271E] h-full transition-[width]"
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
            description: `${stackOk}/3 services online (n8n, AI Engine, Wazuh API). Inspect connection status and endpoints.`,
            icon: 'monitoringApp',
          },
          {
            id: 'network-map',
            title: 'Network map',
            description: `Hub-and-spoke topology of ${stats.active}/${stats.total} active agents. Interactive node exploration.`,
            icon: 'graphApp',
          },
          {
            id: 'users',
            title: 'User management',
            description: 'Kelola akun personel SOC dan otorisasi berjenjang (Admin, Analyst, Viewer).',
            icon: 'usersRolesApp',
          },
          {
            id: 'api-keys',
            title: 'API keys',
            description: 'Penerbitan dan audit token akses M2M untuk AI agent dan integrasi workflow eksternal.',
            icon: 'lock',
          },
        ],
      },
    ],
    [stats, linux, windows, mac, stackOk]
  );

  return (
    <div className="space-y-4">
      {/* Agent KPI Metrics Strip (WUI Unified Stat Bar) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 bg-white border border-[#D3DAE6] rounded-[4px] divide-y sm:divide-y-0 sm:divide-x divide-[#E9EDF3] text-center">
        <div
          className="cursor-pointer hover:bg-[#FAFBFD] py-3 px-3 transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#535966] font-medium">Total agents</div>
          <div className="text-[24px] font-semibold text-[#1A1C21] font-mono tabular-nums leading-tight mt-1">
            {stats.total}
          </div>
          <div className="text-[11px] text-[#69707D] font-mono tabular-nums mt-0.5">
            {stats.rust} Rust · {stats.wazuh} Wazuh
          </div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#FAFBFD] py-3 px-3 transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#535966] font-medium">Active agents</div>
          <div className="text-[24px] font-semibold text-[#007871] font-mono tabular-nums leading-tight mt-1">
            {stats.active}
          </div>
          <div className="text-[11px] text-[#69707D] font-mono tabular-nums mt-0.5">
            {stats.total > 0 ? Math.round((stats.active / stats.total) * 100) : 0}% operational
          </div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#FAFBFD] py-3 px-3 transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#535966] font-medium">Disconnected agents</div>
          <div className="text-[24px] font-semibold text-[#BD271E] font-mono tabular-nums leading-tight mt-1">
            {stats.disconnected}
          </div>
          <div className="text-[11px] text-[#69707D] font-mono tabular-nums mt-0.5">
            {stats.disconnected > 0 && stats.total > 0
              ? `${Math.round((stats.disconnected / stats.total) * 100)}% offline`
              : 'All connected'}
          </div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#FAFBFD] py-3 px-3 transition-colors"
          onClick={() => onNavigate('security-events', { period: '24h' })}
        >
          <div className="text-[12px] text-[#535966] font-medium">Threat events (24h)</div>
          <div className="text-[24px] font-semibold text-[#1A1C21] font-mono tabular-nums leading-tight mt-1">
            {stats.events_total.toLocaleString('en-US')}
          </div>
          <div className="flex items-center justify-center gap-2 mt-0.5 text-[11px] text-[#535966]">
            <span
              onClick={(e) => {
                e.stopPropagation();
                onNavigate('security-events', { severity: ['CRITICAL'], period: '24h' });
              }}
              className="hover:underline cursor-pointer"
              title="Filter Critical events (24h)"
            >
              <span className="font-semibold text-[#BD271E] font-mono tabular-nums">{stats.severity?.CRITICAL || 0}</span> critical
            </span>
            <span className="text-[#D3DAE6]">·</span>
            <span
              onClick={(e) => {
                e.stopPropagation();
                onNavigate('security-events', { severity: ['HIGH'], period: '24h' });
              }}
              className="hover:underline cursor-pointer"
              title="Filter High events (24h)"
            >
              <span className="font-semibold text-[#8A5300] font-mono tabular-nums">{stats.severity?.HIGH || 0}</span> high
            </span>
          </div>
        </div>
      </div>

      {/* Categorized Modules Grid (WUI Panels — clean title, unboxed icons) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {sections.map((section) => (
          <WuiPanel
            key={section.title}
            title={section.title}
            right={
              <span className="text-[11px] text-[#69707D]">
                {section.modules.length} {section.modules.length === 1 ? 'module' : 'modules'}
              </span>
            }
            className={section.wide ? 'lg:col-span-2' : ''}
            bodyClassName={`p-4 grid gap-3 auto-rows-fr ${
              section.wide ? 'grid-cols-1 sm:grid-cols-3' : 'grid-cols-1 sm:grid-cols-2'
            }`}
          >
            {section.modules.map((mod) => {
              return (
                <div
                  key={mod.id}
                  onClick={() => onNavigate(mod.id)}
                  className="border border-[#E9EDF3] rounded-[4px] p-3.5 flex items-start gap-3 bg-white transition-colors hover:border-[#006BB4] hover:bg-[#FAFBFD] cursor-pointer group"
                >
                  <WuiIcon type={mod.icon} size={20} className="mt-0.5 text-[#343741]" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-semibold text-[#1A1C21] leading-snug group-hover:text-[#006BB4] transition-colors truncate">
                      {mod.title}
                    </div>
                    <div className="text-[11.5px] text-[#535966] mt-1 line-clamp-3 leading-relaxed">
                      {mod.description}
                    </div>
                    {mod.extra}
                  </div>
                </div>
              );
            })}
          </WuiPanel>
        ))}
      </div>
    </div>
  );
});
