'use client';

import React, { useMemo, useState } from 'react';
import {
  agentRiskMeta,
  agentStatus,
  formatWazuhTime,
  osType,
  type AgentRiskLevel,
  type FleetAgent,
  type FleetHealth,
} from '@/lib/fleet';
import { WuiIcon } from '../wui/WuiIcon';
import { HostRiskBadge, WuiHealth, WuiPageHeader, WuiPanel } from '../wui/WuiPrimitives';

interface NetworkMapViewProps {
  agents: FleetAgent[];
  health?: FleetHealth;
  onSelectAgent?: (agentId: string) => void;
}

type StatusFilter = 'all' | 'active' | 'disconnected';
type RiskFilter = 'all' | AgentRiskLevel;
type GroupMode = 'status' | 'os' | 'risk' | 'flat';

function getOsIcon(os?: string): 'osWindows' | 'osMac' | 'osLinux' {
  const kind = osType(os || '');
  if (kind === 'windows') return 'osWindows';
  if (kind === 'mac') return 'osMac';
  return 'osLinux';
}

function getSubnetPrefix(ip?: string): string {
  const clean = (ip || '').trim();
  const parts = clean.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return clean || 'Tidak diketahui';
}

/**
 * Tampilan Topologi Jaringan & Konektivitas Fleet berbasis elemen Wazuh UI / OUI.
 * Menampilkan status control plane (Wazuh Manager, Fleet API, n8n), node endpoint
 * terstruktur per kelompok status/OS, serta ringkasan subnet jaringan.
 */
export function NetworkMapView({ agents, health, onSelectAgent }: NetworkMapViewProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [groupMode, setGroupMode] = useState<GroupMode>('status');

  const normalized = useMemo(
    () =>
      agents.map((a) => {
        const st = agentStatus(a.status);
        const osKind = osType(a.os);
        const risk = agentRiskMeta(a.risk);
        return {
          agent: a,
          status: st,
          active: st === 'active',
          osKind,
          osLabel: osKind === 'windows' ? 'Windows' : osKind === 'mac' ? 'macOS' : 'Linux',
          isRust: a.type === 'rust',
          subnet: getSubnetPrefix(a.ip),
          risk,
        };
      }),
    [agents]
  );

  const activeCount = normalized.filter((n) => n.active).length;
  const disconnectedCount = normalized.length - activeCount;
  const highRiskCount = normalized.filter((n) => n.risk.level === 'high').length;
  const mediumRiskCount = normalized.filter((n) => n.risk.level === 'medium').length;
  const lowRiskCount = normalized.filter((n) => n.risk.level === 'low').length;
  const rustCount = normalized.filter((n) => n.isRust).length;
  const wazuhCount = normalized.length - rustCount;
  const coveragePct = normalized.length > 0 ? Math.round((activeCount / normalized.length) * 100) : 0;

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return normalized.filter((item) => {
      if (statusFilter === 'active' && !item.active) return false;
      if (statusFilter === 'disconnected' && item.active) return false;
      if (riskFilter !== 'all' && item.risk.level !== riskFilter) return false;
      if (!q) return true;
      return (
        item.agent.name.toLowerCase().includes(q) ||
        item.agent.id.toLowerCase().includes(q) ||
        (item.agent.ip || '').toLowerCase().includes(q) ||
        (item.agent.os || '').toLowerCase().includes(q)
      );
    });
  }, [normalized, searchTerm, statusFilter, riskFilter]);

  const groups = useMemo(() => {
    if (groupMode === 'flat') {
      return [{ id: 'all', title: 'Semua Endpoint Terdaftar', tone: 'primary' as const, items: filtered }];
    }
    if (groupMode === 'risk') {
      const buckets: Array<{ id: AgentRiskLevel; title: string; tone: 'danger' | 'warning' | 'success'; items: typeof filtered }> = [
        { id: 'high', title: 'Kerentanan Tinggi (Butuh Tindakan)', tone: 'danger', items: [] },
        { id: 'medium', title: 'Kerentanan Sedang (Perlu Pantau)', tone: 'warning', items: [] },
        { id: 'low', title: 'Kerentanan Rendah (Normal)', tone: 'success', items: [] },
      ];
      for (const item of filtered) {
        const target = buckets.find((b) => b.id === item.risk.level) || buckets[2];
        target.items.push(item);
      }
      return buckets.filter((b) => b.items.length > 0);
    }
    if (groupMode === 'os') {
      const buckets: Array<{ id: string; title: string; tone: 'primary'; items: typeof filtered }> = [
        { id: 'linux', title: 'Linux Endpoints', tone: 'primary', items: [] },
        { id: 'windows', title: 'Windows Endpoints', tone: 'primary', items: [] },
        { id: 'mac', title: 'macOS Endpoints', tone: 'primary', items: [] },
      ];
      for (const item of filtered) {
        const target = buckets.find((b) => b.id === item.osKind) || buckets[0];
        target.items.push(item);
      }
      return buckets.filter((b) => b.items.length > 0);
    }
    const activeItems = filtered.filter((x) => x.active);
    const offlineItems = filtered.filter((x) => !x.active);
    const out: Array<{ id: string; title: string; tone: 'success' | 'danger'; items: typeof filtered }> = [];
    if (activeItems.length > 0) {
      out.push({ id: 'active', title: 'Active Endpoints (Terhubung)', tone: 'success', items: activeItems });
    }
    if (offlineItems.length > 0) {
      out.push({ id: 'disconnected', title: 'Disconnected Endpoints (Butuh Atensi)', tone: 'danger', items: offlineItems });
    }
    return out;
  }, [filtered, groupMode]);

  const subnets = useMemo(() => {
    const map = new Map<string, { subnet: string; active: number; disconnected: number; hosts: string[] }>();
    for (const item of normalized) {
      const existing = map.get(item.subnet) || {
        subnet: item.subnet,
        active: 0,
        disconnected: 0,
        hosts: [],
      };
      if (item.active) existing.active += 1;
      else existing.disconnected += 1;
      existing.hosts.push(item.agent.name);
      map.set(item.subnet, existing);
    }
    return Array.from(map.values()).sort((a, b) => b.active + b.disconnected - (a.active + a.disconnected));
  }, [normalized]);

  const managerOk = health ? health.wazuh_api && health.n8n : true;

  return (
    <div className="space-y-4">
      <WuiPageHeader
        title={
          <>
            <WuiIcon type="graphApp" size="l" />
            <span>Topologi Jaringan &amp; Konektivitas Fleet</span>
          </>
        }
        description="Pemetaan arsitektur Wazuh Manager, layanan orkestrasi SOAR, distribusi subnet, dan status koneksi tiap endpoint."
        actions={
          <WuiHealth tone={managerOk ? 'success' : 'warning'}>
            {managerOk ? 'Control Plane Online' : 'Sebagian Layanan Degraded'}
          </WuiHealth>
        }
      />

      {/* OUI Split KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 bg-white border border-[#D3DAE6] rounded-[4px] divide-y lg:divide-y-0 lg:divide-x divide-[#E9EDF3]">
        <div className="py-3 px-4">
          <div className="text-[12px] text-[#535966] font-medium">Total Node Fleet</div>
          <div className="text-[22px] font-semibold text-[#1A1C21] font-mono tabular-nums leading-tight mt-1">
            {agents.length + 1}
          </div>
          <div className="text-[11px] text-[#69707D] mt-0.5 font-mono tabular-nums">
            1 Manager / {agents.length} Endpoints
          </div>
        </div>
        <div className="py-3 px-4">
          <div className="text-[12px] text-[#535966] font-medium">Active Endpoints</div>
          <div className="text-[22px] font-semibold text-[#017D73] font-mono tabular-nums leading-tight mt-1">
            {activeCount}
          </div>
          <div className="text-[11px] text-[#69707D] mt-0.5 font-mono tabular-nums">
            {coveragePct}% terhubung
          </div>
        </div>
        <div className="py-3 px-4">
          <div className="text-[12px] text-[#535966] font-medium">Disconnected</div>
          <div className="text-[22px] font-semibold text-[#BD271E] font-mono tabular-nums leading-tight mt-1">
            {disconnectedCount}
          </div>
          <div className="text-[11px] text-[#69707D] mt-0.5">
            {disconnectedCount === 0 ? 'Semua endpoint online' : 'Perlu pengecekan koneksi'}
          </div>
        </div>
        <div className="py-3 px-4">
          <div className="text-[12px] text-[#535966] font-medium">Agent Engine</div>
          <div className="text-[22px] font-semibold text-[#006BB4] font-mono tabular-nums leading-tight mt-1">
            {rustCount} / {wazuhCount}
          </div>
          <div className="text-[11px] text-[#69707D] mt-0.5 font-mono">
            soar-agent / wazuh-agent
          </div>
        </div>
      </div>

      {/* Control Plane Hierarchy */}
      <div className="space-y-0">
        <WuiPanel
          title={
            <span className="flex items-center gap-2 text-[14px] font-semibold text-[#1A1C21]">
              <WuiIcon type="managementApp" size="m" />
              <span>Control Plane &amp; Manager Cluster</span>
            </span>
          }
          subtitle="Node pusat penerima telemetri FIM, syslog agent, dan distribusi Active Response."
          right={
            <span className="text-[11px] font-mono text-[#69707D] tabular-nums">
              {subnets.length} subnet aktif
            </span>
          }
          bodyClassName="p-4"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="border border-[#D3DAE6] rounded-[4px] bg-[#FAFBFD] p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-semibold text-[#1A1C21] flex items-center gap-1.5">
                  <WuiIcon type="node" size="s" className="text-[#006BB4]" />
                  <span>Wazuh Manager</span>
                </span>
                <WuiHealth tone={health?.wazuh_api === false ? 'danger' : 'success'}>
                  {health?.wazuh_api === false ? 'Offline' : 'Active'}
                </WuiHealth>
              </div>
              <div className="mt-2 pt-2 border-t border-[#E9EDF3] text-[11.5px] text-[#535966] space-y-1 font-mono">
                <div>Agent Protocol: TCP :1514</div>
                <div>Enrollment API: TCP :1515 / :55000</div>
              </div>
            </div>

            <div className="border border-[#D3DAE6] rounded-[4px] bg-[#FAFBFD] p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-semibold text-[#1A1C21] flex items-center gap-1.5">
                  <WuiIcon type="compute" size="s" className="text-[#006BB4]" />
                  <span>Fleet Monitor API</span>
                </span>
                <WuiHealth tone="success">Active</WuiHealth>
              </div>
              <div className="mt-2 pt-2 border-t border-[#E9EDF3] text-[11.5px] text-[#535966] space-y-1 font-mono">
                <div>Heartbeat &amp; Poll: HTTP :8080</div>
                <div>Managed Endpoints: {agents.length} node</div>
              </div>
            </div>

            <div className="border border-[#D3DAE6] rounded-[4px] bg-[#FAFBFD] p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-semibold text-[#1A1C21] flex items-center gap-1.5">
                  <WuiIcon type="bolt" size="s" className="text-[#006BB4]" />
                  <span>n8n SOAR Orchestrator</span>
                </span>
                <WuiHealth tone={health?.n8n === false ? 'danger' : 'success'}>
                  {health?.n8n === false ? 'Offline' : 'Active'}
                </WuiHealth>
              </div>
              <div className="mt-2 pt-2 border-t border-[#E9EDF3] text-[11.5px] text-[#535966] space-y-1 font-mono">
                <div>Webhook Engine: HTTP :5678</div>
                <div>Pipeline: Malware, FIM &amp; Phishing</div>
              </div>
            </div>
          </div>
        </WuiPanel>

        {/* Structural 1px OUI connector stem from Control Plane to Endpoint Nodes */}
        <div className="flex justify-center" aria-hidden="true">
          <div className="w-px h-4 bg-[#D3DAE6]" />
        </div>
        <div className="h-px bg-[#D3DAE6] mx-6" aria-hidden="true" />
      </div>

      {/* Filter & Grouping Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 bg-white border border-[#D3DAE6] rounded-[4px] p-3">
        <div className="relative flex-1 min-w-[220px]">
          <WuiIcon type="search" size="s" className="text-[#69707D] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter hostname, ID agent, IP, atau OS..."
            className="w-full h-8 pl-8 pr-3 bg-white border border-[#D3DAE6] rounded-[4px] text-[12px] text-[#1A1C21] placeholder-[#69707D] outline-none focus:border-[#006BB4]"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex border border-[#D3DAE6] rounded-[4px] overflow-hidden divide-x divide-[#D3DAE6] text-[12px]">
            {(
              [
                { id: 'all', label: `Semua (${normalized.length})` },
                { id: 'active', label: `Active (${activeCount})` },
                { id: 'disconnected', label: `Disconnected (${disconnectedCount})` },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setStatusFilter(opt.id)}
                className={`h-8 px-3 font-medium transition-colors cursor-pointer ${
                  statusFilter === opt.id
                    ? 'bg-[#EBF5FB] text-[#006BB4]'
                    : 'bg-white text-[#535966] hover:bg-[#FAFBFD]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <div className="inline-flex border border-[#D3DAE6] rounded-[4px] overflow-hidden divide-x divide-[#D3DAE6] text-[12px]">
            {(
              [
                { id: 'all', label: 'Semua Risiko', colorClass: 'text-[#535966]' },
                { id: 'high', label: `Tinggi (${highRiskCount})`, colorClass: 'text-[#BD271E]' },
                { id: 'medium', label: `Sedang (${mediumRiskCount})`, colorClass: 'text-[#935E00]' },
                { id: 'low', label: `Rendah (${lowRiskCount})`, colorClass: 'text-[#017D73]' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setRiskFilter(opt.id)}
                className={`h-8 px-2.5 font-medium transition-colors cursor-pointer ${
                  riskFilter === opt.id
                    ? 'bg-[#EBF5FB] text-[#006BB4]'
                    : `bg-white ${opt.colorClass} hover:bg-[#FAFBFD]`
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <select
            value={groupMode}
            onChange={(e) => setGroupMode(e.target.value as GroupMode)}
            aria-label="Pengelompokan node endpoint"
            className="h-8 px-2.5 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px] text-[#1A1C21] outline-none focus:border-[#006BB4]"
          >
            <option value="status">Kelompokkan: Status Koneksi</option>
            <option value="risk">Kelompokkan: Tingkat Kerentanan</option>
            <option value="os">Kelompokkan: Sistem Operasi</option>
            <option value="flat">Tampilan Datar (Semua)</option>
          </select>
        </div>
      </div>

      {/* Endpoint Node Groups */}
      {groups.length === 0 ? (
        <WuiPanel>
          <div className="py-6 text-center text-[12px] text-[#69707D]">
            Tidak ada endpoint yang cocok dengan filter pencarian.
          </div>
        </WuiPanel>
      ) : (
        groups.map((grp) => (
          <WuiPanel
            key={grp.id}
            title={
              <span className="flex items-center gap-2 text-[13px] font-semibold text-[#1A1C21]">
                <WuiHealth tone={grp.tone}>{grp.title}</WuiHealth>
                <span className="text-[11px] font-mono text-[#69707D] tabular-nums">({grp.items.length})</span>
              </span>
            }
            bodyClassName="p-4"
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {grp.items.map(({ agent, status, active, isRust }) => (
                <button
                  key={agent.id}
                  type="button"
                  onClick={() => onSelectAgent?.(agent.id)}
                  className="text-left bg-white border border-[#D3DAE6] hover:border-[#006BB4] rounded-[4px] p-3 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="flex items-center gap-2 min-w-0">
                      <WuiIcon type={getOsIcon(agent.os)} size="m" className="shrink-0" />
                      <span className="text-[13px] font-semibold text-[#1A1C21] truncate">
                        {agent.name}
                      </span>
                    </span>
                    <span className="text-[11px] font-mono text-[#69707D] tabular-nums shrink-0">
                      #{agent.id}
                    </span>
                  </div>

                  <div className="mt-2.5 pt-2 border-t border-[#EBEFF5] space-y-1 text-[11.5px]">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[#69707D]">IP Address</span>
                      <span className="font-mono text-[#1A1C21] tabular-nums">{agent.ip || 'any'}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[#69707D]">Engine</span>
                      <span className="font-mono text-[#343741]">
                        {isRust ? 'soar-agent' : 'wazuh-agent'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[#69707D]">OS</span>
                      <span className="text-[#535966] truncate max-w-[160px]" title={agent.os}>
                        {agent.os && agent.os !== 'unknown' ? agent.os : '-'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[#69707D]">Keep Alive</span>
                      <span className="font-mono text-[#535966] tabular-nums">
                        {formatWazuhTime(agent.lastKeepAlive)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2 pt-0.5">
                      <span className="text-[#69707D]">Kerentanan</span>
                      <HostRiskBadge risk={agent.risk} showCount />
                    </div>
                  </div>

                  <div className="mt-2.5 pt-2 border-t border-[#EBEFF5] flex items-center justify-between">
                    <WuiHealth tone={active ? 'success' : status === 'disconnected' ? 'danger' : 'default'}>
                      {active ? 'Active' : status === 'disconnected' ? 'Disconnected' : 'Never connected'}
                    </WuiHealth>
                    <span className="text-[11px] text-[#006BB4] font-medium inline-flex items-center gap-1">
                      <span>Detail</span>
                      <WuiIcon type="arrowRight" size="xs" />
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </WuiPanel>
        ))
      )}

      {/* Subnet Distribution Summary Table */}
      <WuiPanel
        title="Distribusi Subnet &amp; Segmen IP"
        subtitle="Pengelompokan endpoint berdasarkan prefix /24 untuk audit konektivitas jaringan."
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#FAFBFD] border-b border-[#D3DAE6] text-[#535966] text-[11px]">
                <th className="py-2.5 px-4 font-semibold">Subnet / Prefix</th>
                <th className="py-2.5 px-4 font-semibold">Active</th>
                <th className="py-2.5 px-4 font-semibold">Disconnected</th>
                <th className="py-2.5 px-4 font-semibold">Host Terdaftar</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEFF5]">
              {subnets.map((row) => (
                <tr key={row.subnet} className="hover:bg-[#FAFBFD]">
                  <td className="py-2 px-4 font-mono text-[#1A1C21] tabular-nums">{row.subnet}</td>
                  <td className="py-2 px-4 font-mono text-[#017D73] tabular-nums">{row.active}</td>
                  <td className="py-2 px-4 font-mono text-[#BD271E] tabular-nums">{row.disconnected}</td>
                  <td className="py-2 px-4 font-mono text-[11.5px] text-[#535966]">
                    {row.hosts.join(', ')}
                  </td>
                </tr>
              ))}
              {subnets.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-4 px-4 text-center text-[#69707D]">
                    Belum ada data subnet endpoint.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </WuiPanel>
    </div>
  );
}
