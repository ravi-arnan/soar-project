'use client';

import React, { useEffect, useState } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import type { FleetHealth, FleetStats } from '@/lib/fleet';
import { formatWazuhTime } from '@/lib/fleet';
import { DEFAULT_AI_CONFIG, getProviderMeta, type AiConfig } from '@/lib/aiConfig';
import { ApiKeysView } from './ApiKeysView';
import { DynamicSettingsView } from './DynamicSettingsView';
import { WuiHealth, WuiPanel } from '../wui/WuiPrimitives';

export type SettingsTabId = 'general' | 'keys' | 'dynamic-config';

interface SettingsViewProps {
  health?: FleetHealth;
  stats: FleetStats;
  generatedAt: string;
  online: boolean;
  refreshMs: number;
  onRefreshMsChange: (ms: number) => void;
  initialTab?: SettingsTabId;
  userRole?: 'admin' | 'analyst' | 'viewer';
}

interface ComponentResource {
  name: string;
  category: 'core' | 'orchestration' | 'storage' | 'microservice' | 'ai';
  role: string;
  memory: string;
  memPercent: string;
  memPctNum?: number;
  hasLiveMem?: boolean;
  status: string;
  isOk: boolean;
  port?: string;
}

function formatMemMb(mb: number): string {
  if (mb >= 1024) {
    return `${(mb / 1024).toFixed(2)} GB`;
  }
  return `${Number.isInteger(mb) ? mb : mb.toFixed(1)} MB`;
}

export function SettingsView({
  health,
  stats,
  generatedAt,
  online,
  refreshMs,
  onRefreshMsChange,
  initialTab = 'general',
  userRole = 'viewer',
}: SettingsViewProps) {
  const [activeTab, setActiveTab] = useState<SettingsTabId>(initialTab);
  const [prevInitialTab, setPrevInitialTab] = useState(initialTab);
  const [activeAi, setActiveAi] = useState<AiConfig>(DEFAULT_AI_CONFIG);

  if (initialTab !== prevInitialTab) {
    setPrevInitialTab(initialTab);
    setActiveTab(initialTab);
  }

  useEffect(() => {
    if (userRole === 'viewer') return;
    let ignore = false;
    fetch('/api/settings/threat-intel', { cache: 'no-store' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!ignore && data?.ai_config) {
          setActiveAi({ ...DEFAULT_AI_CONFIG, ...data.ai_config });
        }
      })
      .catch(() => {});
    return () => {
      ignore = true;
    };
  }, [userRole]);

  const containerMap = health?.container_stats?.containers ?? {};
  const resolveMem = (candidates: string[]): Pick<ComponentResource, 'memory' | 'memPercent' | 'memPctNum' | 'hasLiveMem'> => {
    let stat = undefined;
    for (const c of candidates) {
      if (containerMap[c]) {
        stat = containerMap[c];
        break;
      }
    }
    if (!stat) {
      const entries = Object.entries(containerMap);
      for (const c of candidates) {
        const found = entries.find(([k]) => k.includes(c));
        if (found) {
          stat = found[1];
          break;
        }
      }
    }
    if (!stat) {
      return { memory: 'Managed', memPercent: '-', hasLiveMem: false };
    }
    if (stat.mem_limit_mb > 0) {
      return {
        memory: `${formatMemMb(stat.mem_used_mb)} / ${formatMemMb(stat.mem_limit_mb)}`,
        memPercent: `${stat.mem_pct.toFixed(1)}%`,
        memPctNum: stat.mem_pct,
        hasLiveMem: true,
      };
    }
    return {
      memory: formatMemMb(stat.mem_used_mb),
      memPercent: '-',
      hasLiveMem: true,
    };
  };

  const components: ComponentResource[] = [
    {
      name: 'Wazuh Indexer (OpenSearch Cluster)',
      category: 'storage',
      role: 'Penyimpanan event terpusat, pengindeksan telemetri FIM & audit log riwayat',
      ...resolveMem(['single-node-wazuh.indexer-1', 'wazuh.indexer']),
      status: health?.wazuh_api ? 'Online' : 'Offline',
      isOk: !!health?.wazuh_api,
      port: ':9200',
    },
    {
      name: 'Wazuh Manager Core (Analysisd)',
      category: 'core',
      role: 'Mesin korelasi aturan Sysmon, decoder rantai proses, dan trigger Active Response',
      ...resolveMem(['single-node-wazuh.manager-1', 'wazuh.manager']),
      status: health?.wazuh_api ? 'Online' : 'Offline',
      isOk: !!health?.wazuh_api,
      port: ':1514, :55000',
    },
    {
      name: 'n8n Orchestrator (Otak SOAR)',
      category: 'orchestration',
      role: 'Eksekusi playbook insiden, evaluasi matriks otonomi, koroborasi VT/MB, dan callback Telegram',
      ...resolveMem(['n8n']),
      status: health?.n8n ? 'Online' : 'Offline',
      isOk: !!health?.n8n,
      port: ':5678',
    },
    {
      name: 'Fleet Web Dashboard (Next.js Standalone)',
      category: 'core',
      role: 'Antarmuka komando pusat armada, session security gate 2FA, dan integrasi MCP',
      ...resolveMem(['fleet-dashboard']),
      status: online ? 'Online' : 'Offline',
      isOk: online,
      port: ':3000',
    },
    {
      name: 'Fleet Monitor & M2M API Engine',
      category: 'microservice',
      role: 'Control plane API, sinkronisasi cache VT/MB server-side, dan SQLite API Key auth',
      ...resolveMem(['fleet-monitor']),
      status: online ? 'Online' : 'Offline',
      isOk: online,
      port: ':8080',
    },
    {
      name: 'MISP Threat Intel Cache & OSINT Sync',
      category: 'microservice',
      role: 'Penyedia indeks indikator kompromi lokal dari feed CIRCL OSINT tanpa kuota',
      ...resolveMem(['misp-index']),
      status: health?.misp ? 'Online' : 'Offline',
      isOk: !!health?.misp,
      port: ':8090',
    },
    {
      name: 'Telegram Decision & Health Loggers',
      category: 'microservice',
      role: 'Registry keputusan HITL, audit trail analis ber-SLA 15m, dan self-aware health checker',
      ...resolveMem(['alert-log']),
      status: health?.alert_log ? 'Online' : 'Offline',
      isOk: !!health?.alert_log,
      port: ':8091',
    },
    {
      name: `AI Reasoning Engine (${activeAi.model} / ${getProviderMeta(activeAi.provider).shortLabel})`,
      category: 'ai',
      role: activeAi.fallback_enabled
        ? `Triage kontekstual dinamis (Fallback: ${activeAi.fallback_model})`
        : 'Triage kontekstual dinamis (Fallback nonaktif)',
      memory: 'Offloaded API',
      memPercent: '-',
      hasLiveMem: false,
      status: activeAi.enabled ? (health?.gemini ? 'Online' : 'Key Missing') : 'Disabled',
      isOk: activeAi.enabled ? !!health?.gemini : false,
      port: 'Cloud / Custom API',
    },
  ];

  const endpoints = [
    { method: 'GET', path: '/api/fleet', desc: 'Status agent + kesehatan stack' },
    { method: 'GET', path: '/api/events', desc: 'Threat events untuk dashboard' },
    { method: 'GET', path: '/api/keys', desc: 'Daftar API Key machine-to-machine' },
    { method: 'GET', path: '/api/settings/threat-intel', desc: 'Konfigurasi AI & Threat Intel (masked)' },
    { method: 'POST', path: '/api/auth/2fa/request', desc: 'Kirim kode OTP 2FA ke email & Telegram' },
    { method: 'POST', path: '/api/auth/2fa/verify', desc: 'Verifikasi kode OTP & pasang cookie sesi' },
    { method: 'POST', path: '/api/commands', desc: 'Karantina, scan, dan mitigasi aktif' },
    { method: 'POST', path: '/webhook-log', desc: 'Node n8n Log ke Fleet menulis alert' },
  ];

  return (
    <div className="space-y-4">
      {/* OUI Tabs */}
      <div className="flex flex-wrap items-center gap-6 border-b border-[#D3DAE6] text-[13px]">
        <button
          type="button"
          onClick={() => setActiveTab('general')}
          className={`flex items-center gap-1.5 pb-2.5 -mb-px font-medium transition-colors cursor-pointer border-b-2 ${
            activeTab === 'general'
              ? 'border-[#006BB4] text-[#006BB4] font-semibold'
              : 'border-transparent text-[#535966] hover:text-[#1A1C21]'
          }`}
        >
          <WuiIcon type="controlsHorizontal" size="s" />
          <span>General &amp; Diagnostics</span>
        </button>
        {userRole !== 'viewer' && (
          <button
            type="button"
            onClick={() => setActiveTab('dynamic-config')}
            className={`flex items-center gap-1.5 pb-2.5 -mb-px font-medium transition-colors cursor-pointer border-b-2 ${
              activeTab === 'dynamic-config'
                ? 'border-[#006BB4] text-[#006BB4] font-semibold'
                : 'border-transparent text-[#535966] hover:text-[#1A1C21]'
            }`}
          >
            <WuiIcon type="machineLearningApp" size="s" className="ouiIcon--mono" />
            <span>AI Engine &amp; Threat Intel</span>
          </button>
        )}
        {userRole === 'admin' && (
          <button
            type="button"
            onClick={() => setActiveTab('keys')}
            className={`flex items-center gap-1.5 pb-2.5 -mb-px font-medium transition-colors cursor-pointer border-b-2 ${
              activeTab === 'keys'
                ? 'border-[#006BB4] text-[#006BB4] font-semibold'
                : 'border-transparent text-[#535966] hover:text-[#1A1C21]'
            }`}
          >
            <WuiIcon type="lock" size="s" />
            <span>API Keys &amp; Agent Access</span>
          </button>
        )}
      </div>

      {activeTab === 'dynamic-config' && userRole !== 'viewer' ? (
        <DynamicSettingsView userRole={userRole} />
      ) : activeTab === 'keys' && userRole === 'admin' ? (
        <ApiKeysView />
      ) : (
        <div className="space-y-4">
          {/* Live Status Summary Strip */}
          <div className="bg-white border border-[#D3DAE6] rounded-[4px] grid grid-cols-1 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-[#E9EDF3]">
            <div className="px-4 py-3">
              <div className="text-[12px] font-medium text-[#535966]">
                Services Healthy
              </div>
              <div className="text-[20px] font-semibold font-mono tabular-nums text-[#006BB4] mt-0.5">
                {components.filter((c) => c.isOk).length} / {components.length}
              </div>
              <div className="text-[11px] text-[#69707D] mt-0.5">Status probe live backend</div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[12px] font-medium text-[#535966]">
                Active Fleet Agents
              </div>
              <div className="text-[20px] font-semibold font-mono tabular-nums text-[#007871] mt-0.5">
                {stats.active} / {stats.total}
              </div>
              <div className="text-[11px] text-[#69707D] mt-0.5">Rust: {stats.rust} · Wazuh: {stats.wazuh}</div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[12px] font-medium text-[#535966]">
                Events (24h)
              </div>
              <div className="text-[20px] font-semibold font-mono tabular-nums text-[#1A1C21] mt-0.5">
                {stats.events_total}
              </div>
              <div className="text-[11px] text-[#69707D] mt-0.5">All-time: {stats.events_all_time ?? stats.events_total}</div>
            </div>
            <div className="px-4 py-3">
              <div className="text-[12px] font-medium text-[#535966]">
                Transmission Mode
              </div>
              <div className="text-[14px] font-semibold text-[#1A1C21] mt-1.5">
                Hash-Only JSON (&lt;2 KB)
              </div>
              <div className="text-[11px] text-[#69707D] mt-0.5">Tanpa kirim berkas utuh</div>
            </div>
          </div>

          {/* Rincian Komponen Arsitektur Utama */}
          <WuiPanel
            title="Rincian Komponen Arsitektur Utama (Status &amp; Konsumsi Memori)"
            accentColor="#006BB4"
            right={
              <span className="text-[11px] font-mono text-[#535966]">
                {components.length} layanan
              </span>
            }
            bodyClassName="p-0"
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px]">
                <thead>
                  <tr className="text-[#535966] text-[12px] font-semibold border-b border-[#D3DAE6]">
                    <th className="py-2.5 px-4">Komponen &amp; Peran</th>
                    <th className="py-2.5 px-3">Port / Jalur</th>
                    <th className="py-2.5 px-3">Beban Memori</th>
                    <th className="py-2.5 px-3">Rasio Limit</th>
                    <th className="py-2.5 px-4 text-left">Status Operasional</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E9EDF3]">
                  {components.map((comp) => (
                    <tr key={comp.name} className="hover:bg-[#FAFBFD] transition-colors">
                      <td className="py-2.5 px-4">
                        <div className="font-medium text-[#1A1C21]">{comp.name}</div>
                        <div className="text-[11px] text-[#535966] mt-0.5">{comp.role}</div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-[#535966] tabular-nums">
                        {comp.port || '-'}
                      </td>
                      <td
                        className={`py-2.5 px-3 font-mono font-semibold tabular-nums ${
                          comp.hasLiveMem ? 'text-[#006BB4]' : 'text-[#535966]'
                        }`}
                      >
                        {comp.memory}
                      </td>
                      <td
                        className={`py-2.5 px-3 font-mono font-medium tabular-nums ${
                          comp.memPctNum === undefined
                            ? 'text-[#535966]'
                            : comp.memPctNum >= 85
                              ? 'text-[#BD271E]'
                              : comp.memPctNum >= 70
                                ? 'text-[#B25E09]'
                                : 'text-[#017D73]'
                        }`}
                      >
                        {comp.memPercent}
                      </td>
                      <td className="py-2.5 px-4 text-left">
                        <WuiHealth tone={comp.isOk ? 'success' : 'warning'}>
                          {comp.status}
                        </WuiHealth>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </WuiPanel>

          {/* Preferensi & Data Status Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <WuiPanel title="Preferences" accentColor="#006BB4">
              <div className="flex items-center justify-between py-1">
                <div>
                  <div className="text-[13px] font-medium text-[#1A1C21]">Refresh interval</div>
                  <div className="text-[12px] text-[#535966]">
                    Seberapa sering dashboard menarik data fleet
                  </div>
                </div>
                <select
                  value={refreshMs}
                  onChange={(e) => onRefreshMsChange(Number(e.target.value))}
                  className="h-8 px-2.5 rounded-[4px] border border-[#D3DAE6] text-[12px] bg-white cursor-pointer focus:outline-none focus:border-[#006BB4]"
                >
                  <option value={5000}>5 detik</option>
                  <option value={10000}>10 detik</option>
                  <option value={30000}>30 detik</option>
                </select>
              </div>
            </WuiPanel>

            <WuiPanel
              title={
                <span className="flex items-center gap-2 text-[13px] font-semibold text-[#1A1C21]">
                  <WuiIcon type="database" size="m" className="text-[#006BB4]" />
                  <span>Data status</span>
                </span>
              }
              accentColor="#017D73"
            >
              <div className="divide-y divide-[#E9EDF3] text-[12px]">
                <div className="flex items-center justify-between py-2">
                  <div className="flex items-center gap-2">
                    {online ? (
                      <WuiIcon type="checkInCircleFilled" size="m" className="text-[#017D73]" />
                    ) : (
                      <WuiIcon type="crossInCircleFilled" size="m" className="text-[#BD271E]" />
                    )}
                    <span className="font-medium text-[#1A1C21]">Backend fleet</span>
                  </div>
                  <span className="text-[#535966] font-mono text-[11.5px]">
                    {online ? 'Terjangkau (:8080)' : 'Tidak terjangkau'}
                  </span>
                </div>
                <div className="flex items-center justify-between py-2">
                  <div className="flex items-center gap-2">
                    <WuiIcon type="checkInCircleFilled" size="m" className="text-[#017D73]" />
                    <span className="font-medium text-[#1A1C21]">Agent aktif</span>
                  </div>
                  <span className="text-[#535966] font-mono tabular-nums text-[11.5px]">
                    {stats.active}/{stats.total} endpoint ({stats.rust} Rust)
                  </span>
                </div>
                <div className="flex items-center justify-between py-2">
                  <div className="flex items-center gap-2">
                    <WuiIcon type="checkInCircleFilled" size="m" className="text-[#017D73]" />
                    <span className="font-medium text-[#1A1C21]">Event tercatat (24h)</span>
                  </div>
                  <span className="text-[#535966] font-mono tabular-nums text-[11.5px]">
                    {stats.events_total?.toLocaleString('en-US') || 0} (24h) /{' '}
                    {(stats.events_all_time ?? stats.events_total ?? 0).toLocaleString('en-US')} total
                  </span>
                </div>
                <div className="pt-2 text-[11.5px] text-[#535966]">
                  Update terakhir: <span className="font-mono">{generatedAt ? formatWazuhTime(generatedAt) : '-'}</span>
                </div>
              </div>
            </WuiPanel>
          </div>

          {/* Endpoints */}
          <WuiPanel
            title={
              <span className="flex items-center gap-2 text-[13px] font-semibold text-[#1A1C21]">
                <WuiIcon type="pulse" size="m" className="text-[#006BB4]" />
                <span>Backend endpoints</span>
              </span>
            }
            subtitle="Dashboard rewrite /api/* ke fleet-monitor :8080, Webhook n8n di :5678"
            accentColor="#006BB4"
            bodyClassName="p-0"
          >
            <div className="divide-y divide-[#E9EDF3]">
              {endpoints.map((ep) => (
                <div key={ep.path} className="px-4 py-2 flex items-center justify-between gap-2 text-[12px]">
                  <div className="flex items-center gap-2 font-mono">
                    <span
                      className={`text-[11px] font-semibold w-10 ${
                        ep.method === 'GET' ? 'text-[#006BB4]' : 'text-[#935E00]'
                      }`}
                    >
                      {ep.method}
                    </span>
                    <span className="text-[#1A1C21]">{ep.path}</span>
                  </div>
                  <span className="text-[#535966]">{ep.desc}</span>
                </div>
              ))}
            </div>
          </WuiPanel>
        </div>
      )}
    </div>
  );
}
