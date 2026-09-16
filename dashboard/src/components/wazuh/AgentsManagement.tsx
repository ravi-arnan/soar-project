'use client';

import React, { useMemo, useState } from 'react';
import {
  PlusCircle,
  Download,
  Settings,
  Eye,
  Link2,
  RefreshCw,
  Search,
  Maximize2,
  ChevronRight,
} from 'lucide-react';
import { agentStatus, formatWazuhTime, osType } from '@/lib/fleet';
import type { FleetAgent } from '@/lib/fleet';

interface AgentsManagementProps {
  onSelectAgent: (agentId: string) => void;
  /** Fleet live dari /api/fleet. */
  agents: FleetAgent[];
  /** Buka view Settings (opsional; tombol gear disembunyikan bila tak ada). */
  onOpenSettings?: () => void;
}

/** Keliling donut status (r=38), disamakan dengan desain Wazuh. */
const DONUT_CIRCUMFERENCE = 240;

export function AgentsManagement({ onSelectAgent, onOpenSettings, agents: fleetAgents }: AgentsManagementProps) {
  const [searchTerm, setSearchTerm] = useState('');

  /** Unduh tabel agent sebagai CSV (data live yang tampil). */
  const exportCsv = () => {
    const cell = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const lines = agents.map((a) =>
      [a.id, a.name, a.ip, a.groups.join(';'), a.os, a.version, a.lastKeepAlive, a.status]
        .map(cell)
        .join(',')
    );
    const blob = new Blob(
      [[['id', 'name', 'ip', 'groups', 'os', 'version', 'last_keep_alive', 'status'].join(','), ...lines].join('\n')],
      { type: 'text/csv' }
    );
    const url = URL.createObjectURL(blob);
    const el = document.createElement('a');
    el.href = url;
    el.download = 'agents.csv';
    el.click();
    URL.revokeObjectURL(url);
  };

  // Petakan agent fleet -> bentuk tabel ala Wazuh Dashboard.
  const agents = useMemo(
    () =>
      fleetAgents.map((a) => ({
        id: a.id,
        name: a.name,
        ip: a.ip || 'any',
        groups: ['default', a.type === 'rust' ? 'soar-agent' : 'wazuh'],
        os: a.os && a.os !== 'unknown' ? a.os : '-',
        osType: osType(a.os),
        clusterNode: '-',
        version: a.version || '-',
        regDate: '-',
        lastKeepAlive: formatWazuhTime(a.lastKeepAlive),
        status: agentStatus(a.status),
      })),
    [fleetAgents]
  );

  const total = agents.length;
  const activeCount = agents.filter((a) => a.status === 'active').length;
  const disconnectedCount = agents.filter((a) => a.status === 'disconnected').length;
  const neverCount = agents.filter((a) => a.status === 'never_connected').length;
  const coverage = total ? ((activeCount / total) * 100).toFixed(2) : '0.00';
  const arc = (n: number) =>
    total ? Math.round((n / total) * DONUT_CIRCUMFERENCE) : 0;
  const arcNever = arc(neverCount);
  const arcActive = arc(activeCount);
  const arcDisconnected = arc(disconnectedCount);
  const lastRegistered = agents.length ? agents[agents.length - 1].name : '-';
  const mostActive = agents.find((a) => a.status === 'active')?.name || '-';

  const filteredAgents = agents.filter(
    (a) =>
      a.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.id.includes(searchTerm) ||
      a.ip.includes(searchTerm)
  );

  return (
    <div className="space-y-4">
      {/* 3 Top Cards: Status, Details, Evolution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Status Donut */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4 relative pt-6">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white border border-[#D3DAE6] px-3 py-0.5 rounded-full text-[10px] font-bold tracking-wider text-[#1A1C21] uppercase">
            STATUS
          </div>

          <div className="flex items-center justify-center gap-6 h-36">
            <div className="relative w-28 h-28 flex items-center justify-center">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#00A389"
                  strokeWidth="18"
                  strokeDasharray={`${arcActive} ${DONUT_CIRCUMFERENCE - arcActive}`}
                  strokeDashoffset="0"
                />
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#BD271E"
                  strokeWidth="18"
                  strokeDasharray={`${arcDisconnected} ${DONUT_CIRCUMFERENCE - arcDisconnected}`}
                  strokeDashoffset={`-${arcActive}`}
                />
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#98A2B3"
                  strokeWidth="18"
                  strokeDasharray={`${arcNever} ${DONUT_CIRCUMFERENCE - arcNever}`}
                  strokeDashoffset={`-${arcActive + arcDisconnected}`}
                />
              </svg>
            </div>

            <div className="text-[11px] space-y-1.5 text-[#5A626F]">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#00A389]"></span>
                <span>Active</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#BD271E]"></span>
                <span>Disconnected</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#98A2B3]"></span>
                <span>Never Connected</span>
              </div>
            </div>
          </div>
        </div>

        {/* Details Grid */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4 relative pt-6">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white border border-[#D3DAE6] px-3 py-0.5 rounded-full text-[10px] font-bold tracking-wider text-[#1A1C21] uppercase">
            DETAILS
          </div>

          <div className="grid grid-cols-4 gap-2 text-center border-b border-[#EBEFF5] pb-3">
            <div>
              <div className="text-[11px] text-[#5A626F]">Active</div>
              <div className="text-[20px] font-semibold text-[#006BB4]">{activeCount}</div>
            </div>
            <div>
              <div className="text-[11px] text-[#5A626F]">Disconnected</div>
              <div className="text-[20px] font-semibold text-[#006BB4]">{disconnectedCount}</div>
            </div>
            <div>
              <div className="text-[11px] text-[#5A626F]">Never connected</div>
              <div className="text-[20px] font-semibold text-[#006BB4]">{neverCount}</div>
            </div>
            <div>
              <div className="text-[11px] text-[#5A626F]">Coverage</div>
              <div className="text-[16px] font-semibold text-[#1A1C21] mt-0.5">{coverage}%</div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-3 text-[12px]">
            <div>
              <div className="text-[#8A94A6] text-[11px]">Last registered agent</div>
              <div className="font-medium text-[#006BB4] hover:underline cursor-pointer truncate">
                {lastRegistered}
              </div>
            </div>
            <div>
              <div className="text-[#8A94A6] text-[11px]">Most active agent</div>
              <div className="font-medium text-[#006BB4] hover:underline cursor-pointer truncate">
                {mostActive}
              </div>
            </div>
          </div>
        </div>

        {/* Evolution Line Chart */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4 relative pt-6">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white border border-[#D3DAE6] px-3 py-0.5 rounded-full text-[10px] font-bold tracking-wider text-[#1A1C21] uppercase">
            EVOLUTION
          </div>

          <div className="h-36 flex flex-col justify-between">
            <svg viewBox="0 0 300 100" className="w-full h-24 overflow-visible">
              <line x1="0" y1="20" x2="300" y2="20" stroke="#7B61FF" strokeWidth="2" />
              <circle cx="50" cy="20" r="3" fill="#7B61FF" />
              <circle cx="150" cy="20" r="3" fill="#7B61FF" />
              <circle cx="250" cy="20" r="3" fill="#7B61FF" />

              <line x1="0" y1="65" x2="300" y2="65" stroke="#006BB4" strokeWidth="2" />
              <circle cx="50" cy="65" r="3" fill="#006BB4" />
              <circle cx="150" cy="65" r="3" fill="#006BB4" />
              <circle cx="250" cy="65" r="3" fill="#006BB4" />

              <line x1="0" y1="85" x2="300" y2="85" stroke="#00A389" strokeWidth="2" />
              <circle cx="50" cy="85" r="3" fill="#00A389" />
              <circle cx="150" cy="85" r="3" fill="#00A389" />
              <circle cx="250" cy="85" r="3" fill="#00A389" />
            </svg>

            <div className="flex justify-between text-[10px] text-[#8A94A6]">
              <span>2026-01-19 00:00</span>
              <span>2026-01-21 00:00</span>
              <span>2026-01-23 00:00</span>
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex items-center gap-2">
        <div className="flex-1 flex items-center bg-white border border-[#D3DAE6] rounded h-9 px-3">
          <input
            type="text"
            placeholder="Filter or search agent"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full text-[13px] bg-transparent outline-none placeholder-[#8A94A6]"
          />
        </div>
        <button className="h-9 px-4 bg-[#006BB4] hover:bg-[#005593] text-white rounded font-medium text-[13px] flex items-center gap-2 transition-colors cursor-pointer">
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Agents Table Card */}
      <div className="bg-white border border-[#D3DAE6] rounded p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-[14px] font-semibold text-[#1A1C21]">Agents ({agents.length})</div>
          <div className="flex items-center gap-4 text-[12px]">
            <a
              href="https://github.com/ravi-arnan/soar-project/tree/main/deploy"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-[#006BB4] hover:underline font-medium"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Deploy new agent</span>
            </a>
            <button
              onClick={exportCsv}
              className="flex items-center gap-1 text-[#006BB4] hover:underline font-medium"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export formatted</span>
            </button>
            {onOpenSettings && (
              <button onClick={onOpenSettings} className="text-[#5A626F] hover:text-[#1A1C21]">
                <Settings className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        <div className="overflow-x-auto border border-[#EBEFF5] rounded">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F] font-semibold">
                <th className="py-2.5 px-3">ID ↑</th>
                <th className="py-2.5 px-3">Name</th>
                <th className="py-2.5 px-3">IP</th>
                <th className="py-2.5 px-3">Group(s)</th>
                <th className="py-2.5 px-3">OS</th>
                <th className="py-2.5 px-3">Cluster node</th>
                <th className="py-2.5 px-3">Version</th>
                <th className="py-2.5 px-3">Registration date</th>
                <th className="py-2.5 px-3">Last keep alive</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEFF5]">
              {filteredAgents.map((agent) => (
                <tr
                  key={agent.id}
                  className="hover:bg-[#F8FAFC] transition-colors cursor-pointer"
                  onClick={() => onSelectAgent(agent.id)}
                >
                  <td className="py-2 px-3 font-medium text-[#006BB4] hover:underline">{agent.id}</td>
                  <td className="py-2 px-3 font-medium text-[#1A1C21]">{agent.name}</td>
                  <td className="py-2 px-3 text-[#5A626F] font-mono">{agent.ip}</td>
                  <td className="py-2 px-3">
                    <div className="flex flex-wrap gap-1">
                      {agent.groups.map((grp) => (
                        <span
                          key={grp}
                          className="bg-[#F0F4F8] border border-[#D3DAE6] text-[#5A626F] px-1.5 py-0.5 rounded text-[10px]"
                        >
                          {grp}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 px-3 text-[#1A1C21] whitespace-nowrap">{agent.os}</td>
                  <td className="py-2 px-3 text-[#5A626F]">{agent.clusterNode}</td>
                  <td className="py-2 px-3 text-[#5A626F] font-mono">{agent.version}</td>
                  <td className="py-2 px-3 text-[#5A626F] whitespace-nowrap">{agent.regDate}</td>
                  <td className="py-2 px-3 text-[#5A626F] whitespace-nowrap">{agent.lastKeepAlive}</td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <span className="flex items-center gap-1.5 font-medium text-[11px]">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          agent.status === 'active'
                            ? 'bg-[#00A389]'
                            : agent.status === 'disconnected'
                            ? 'bg-[#BD271E]'
                            : 'bg-[#98A2B3]'
                        }`}
                      ></span>
                      <span className="capitalize">{agent.status.replace('_', ' ')}</span>
                    </span>
                  </td>
                  <td className="py-2 px-3 text-right">
                    <div className="flex items-center justify-end gap-2 text-[#006BB4]">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAgent(agent.id);
                        }}
                        title="View agent details"
                        className="hover:text-[#005593]"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          const user = agent.os?.toLowerCase().includes('windows') ? 'Administrator' : 'ravi';
                          const cmd = `ssh ${user}@${agent.ip}`;
                          if (window.confirm(`Buka terminal lokal:\n${cmd}`)) {
                            try {
                              navigator.clipboard?.writeText(cmd);
                            } catch {}
                          }
                        }}
                        title={`SSH ke agent ini (${agent.ip})`}
                        className="hover:text-[#00A389]"
                      >
                        <span className="font-mono text-[10px] font-bold">&gt;_</span>
                      </button>
                      <button
                        onClick={(e) => e.stopPropagation()}
                        title="Link"
                        className="hover:text-[#005593]"
                      >
                        <Link2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination footer */}
        <div className="flex items-center justify-between mt-3 text-[12px] text-[#5A626F]">
          <div className="flex items-center gap-2">
            <span>Rows per page: 15</span>
          </div>
          <div className="flex items-center gap-2">
            <span>‹</span>
            <span className="font-semibold text-[#006BB4]">1</span>
            <span>2</span>
            <span>3</span>
            <span>›</span>
          </div>
        </div>
      </div>
    </div>
  );
}
