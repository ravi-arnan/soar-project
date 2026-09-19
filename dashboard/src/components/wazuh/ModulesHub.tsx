'use client';

import React from 'react';
import {
  ShieldAlert,
  FileCheck2,
  ShieldCheck,
  Box,
  Server,
  HeartPulse,
  Network,
} from 'lucide-react';

import type { FleetAgent, FleetHealth, FleetStats } from '@/lib/fleet';

interface ModulesHubProps {
  onNavigate: (moduleKey: string) => void;
  /** Ringkasan fleet dari /api/fleet (live). */
  stats: FleetStats;
  agents: FleetAgent[];
  health?: FleetHealth;
}

export function ModulesHub({ onNavigate, stats, agents, health }: ModulesHubProps) {
  const linux = agents.filter((a) => (a.os || '').toLowerCase().includes('linux')).length;
  const windows = agents.filter((a) => (a.os || '').toLowerCase().includes('windows')).length;
  const stackOk = [health?.n8n, health?.gemini, health?.wazuh_api].filter(Boolean).length;
  const sections = [
    {
      title: 'SECURITY INFORMATION MANAGEMENT',
      modules: [
        {
          id: 'security-events',
          title: 'Security events',
          description:
            'Browse through your security alerts, identifying issues and threats in your environment.',
          icon: ShieldAlert,
        },
        {
          id: 'integrity-monitoring',
          title: 'Integrity monitoring',
          description:
            'Alerts related to file changes, including permissions, content, ownership and attributes.',
          icon: FileCheck2,
        },
      ],
    },
    {
      title: 'AUDITING AND POLICY MONITORING',
      modules: [
        {
          id: 'mitre',
          title: 'MITRE ATT&CK',
          description:
            'Pemetaan playbook n8n ke teknik MITRE ATT&CK — 6 playbook, 10 teknik unik, 4 fase.',
          icon: ShieldCheck,
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
            'Verdict gabungan VirusTotal + OTX atas file mencurigakan via pipeline n8n.',
          icon: Box,
        },
        
      ],
    },
    {
      title: 'FLEET OVERVIEW',
      modules: [
        {
          id: 'agents',
          title: 'Fleet inventory',
          description: `${stats.active}/${stats.total} aktif — Linux ${linux}, Windows ${windows}, ${stats.rust} endpoint.`,
          icon: Server,
        },
        {
          id: 'settings',
          title: 'Stack health',
          description: `${stackOk}/3 layanan hidup (n8n, AI, Wazuh API). Lihat status dan endpoint backend.`,
          icon: HeartPulse,
        },
        {
          id: 'network-map',
          title: 'Network map',
          description: `Topologi hub-and-spoke ${stats.active}/${stats.total} agent aktif. Klik node untuk detail.`,
          icon: Network,
        },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      {/* Agent KPI Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Total agents</div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">{stats.total}</div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Active agents</div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">{stats.active}</div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Disconnected agents</div>
          <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">{stats.disconnected}</div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('security-events')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Threat events</div>
          <div className="text-[32px] font-semibold text-[#64748B] leading-tight mt-1">{stats.events_total}</div>
        </div>
      </div>

      {/* 2x2 Category Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
        {sections.map((section) => (
          <div
            key={section.title}
            className="relative border border-[#D3DAE6] rounded bg-white p-5 pt-7"
          >
            {/* Pill Header Badge */}
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white border border-[#D3DAE6] px-4 py-0.5 rounded-full text-[11px] font-bold tracking-wider text-[#1A1C21] uppercase whitespace-nowrap shadow-xs">
              {section.title}
            </div>

            {/* Modules Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              {section.modules.map((mod) => {
                const Icon = mod.icon;
                return (
                  <div
                    key={mod.id}
                    onClick={() => {
                      onNavigate(mod.id);
                    }}
                    className={`border border-[#D3DAE6] rounded p-3.5 flex items-start gap-3 bg-white transition-all shadow-xs ${
                      'hover:border-[#006BB4] hover:bg-[#F8FAFC] cursor-pointer group'
                    }`}
                  >
                    <div
                      className={`mt-0.5 p-2 rounded bg-[#F5F7FA] text-[#006BB4] shrink-0 ${
                        'group-hover:bg-[#EBF5FB] group-hover:text-[#005593]'
                      } transition-colors`}
                    >
                      <Icon className="w-5 h-5" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <div
                          className={`text-[13px] font-semibold text-[#1A1C21] leading-snug ${
                            'group-hover:text-[#006BB4]'
                          } transition-colors`}
                        >
                          {mod.title}
                        </div>
                      </div>
                      <div className="text-[11px] text-[#5A626F] mt-1 line-clamp-3 leading-relaxed">
                        {mod.description}
                      </div>
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
}
