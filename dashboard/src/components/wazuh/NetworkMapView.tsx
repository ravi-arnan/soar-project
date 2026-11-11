'use client';

import React, { useMemo } from 'react';
import { Network } from 'lucide-react';
import type { FleetAgent } from '@/lib/fleet';

interface NetworkMapViewProps {
  agents: FleetAgent[];
  onSelectAgent?: (agentId: string) => void;
}

const MAP_WIDTH = 720;
const MAP_HEIGHT = 460;
const CX = MAP_WIDTH / 2;
const CY = MAP_HEIGHT / 2;

/**
 * Peta topologi jaringan hub-and-spoke enterprise SOC:
 * Server SOAR Central Hub di tengah dengan spoke terarah ke setiap endpoint agent.
 */
export function NetworkMapView({ agents, onSelectAgent }: NetworkMapViewProps) {
  const nodes = useMemo(() => {
    const n = agents.length || 1;
    const rx = MAP_WIDTH / 2 - 110;
    const ry = MAP_HEIGHT / 2 - 80;
    return agents.map((a, i) => {
      const ang = (2 * Math.PI * i) / n - Math.PI / 2;
      return {
        agent: a,
        x: CX + rx * Math.cos(ang),
        y: CY + ry * Math.sin(ang),
        active: (a.status || '').toLowerCase() === 'active',
        isRust: a.type === 'rust',
        os: (a.os || '').toLowerCase(),
      };
    });
  }, [agents]);

  const activeCount = nodes.filter((d) => d.active).length;

  return (
    <div className="space-y-4">
      {/* KPI Header */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Node fleet</div>
          <div className="text-[32px] font-semibold text-[#006BB4] font-mono tabular-nums leading-tight mt-1">
            {agents.length + 1}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">1 Manager · {agents.length} Endpoints</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Agent active</div>
          <div className="text-[32px] font-semibold text-[#00A389] font-mono tabular-nums leading-tight mt-1">
            {activeCount}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">
            {agents.length > 0 ? Math.round((activeCount / agents.length) * 100) : 0}% terhubung
          </div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Disconnected</div>
          <div className="text-[32px] font-semibold text-[#BD271E] font-mono tabular-nums leading-tight mt-1">
            {nodes.length - activeCount}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">
            {nodes.length - activeCount === 0 ? 'Semua endpoint online' : 'Perlu atensi'}
          </div>
        </div>
      </div>

      {/* Network Topology Graph */}
      <div className="bg-white border border-[#D3DAE6] rounded p-4 overflow-hidden">
        <div className="flex items-center justify-between border-b border-[#EBEFF5] px-1 pb-3">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-[#006BB4]" />
            <h2 className="text-[13px] font-bold text-[#1A1C21] uppercase tracking-wide">
              Topologi Fleet & Komando Pusat (Hub-and-Spoke)
            </h2>
          </div>
          <div className="text-[11px] font-mono text-[#8A94A6]">
            Engine: SVG Vector · Status Realtime
          </div>
        </div>

        <div className="relative w-full flex items-center justify-center py-2">
          <svg viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`} className="w-full max-h-[460px] select-none">
            {/* Background Grid Pattern */}
            <defs>
              <pattern id="topoGrid" width="30" height="30" patternUnits="userSpaceOnUse">
                <circle cx="15" cy="15" r="0.8" fill="#D3DAE6" opacity="0.6" />
              </pattern>
            </defs>
            <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="url(#topoGrid)" />

            {/* Connection Spoke Lines */}
            {nodes.map(({ agent, x, y, active }) => (
              <g key={`edge-${agent.id}`}>
                {/* Glow underlay */}
                <line
                  x1={CX}
                  y1={CY}
                  x2={x}
                  y2={y}
                  stroke={active ? '#00A389' : '#BD271E'}
                  strokeWidth="3"
                  opacity="0.15"
                />
                {/* Main line */}
                <line
                  x1={CX}
                  y1={CY}
                  x2={x}
                  y2={y}
                  stroke={active ? '#00A389' : '#BD271E'}
                  strokeWidth="1.5"
                  strokeDasharray={active ? undefined : '5 4'}
                  opacity={active ? '0.85' : '0.5'}
                />
              </g>
            ))}

            {/* Central SOAR Hub */}
            <g transform={`translate(${CX},${CY})`}>
              {/* Outer soft shadow */}
              <rect
                x="-95"
                y="-30"
                width="190"
                height="60"
                rx="6"
                fill="#F8FAFC"
                stroke="#006BB4"
                strokeWidth="1.5"
              />
              <rect
                x="-91"
                y="-26"
                width="182"
                height="52"
                rx="4"
                fill="#FFFFFF"
              />
              {/* Blue accent indicator */}
              <rect
                x="-91"
                y="-26"
                width="4"
                height="52"
                rx="2"
                fill="#006BB4"
              />
              {/* Core Status Dot */}
              <circle cx="75" cy="-14" r="3.5" fill="#00A389" />
              <text x="-76" y="-8" fill="#1A1C21" fontSize="11" fontWeight="700">
                SOAR CENTRAL HUB
              </text>
              <text x="-76" y="8" fill="#5A626F" fontSize="9" fontFamily="monospace">
                Wazuh Manager :1514
              </text>
              <text x="-76" y="19" fill="#8A94A6" fontSize="8.5" fontFamily="monospace">
                n8n Workflow + Fleet API
              </text>
            </g>

            {/* Endpoint Agent Nodes */}
            {nodes.map(({ agent, x, y, active, isRust, os }) => {
              const displayName =
                agent.name.length > 15 ? `${agent.name.slice(0, 13)}…` : agent.name;
              const isWin = os.includes('win');

              return (
                <g
                  key={agent.id}
                  transform={`translate(${x},${y})`}
                  onClick={() => onSelectAgent?.(agent.id)}
                  className="transition-transform duration-150 hover:scale-105"
                  style={{ cursor: onSelectAgent ? 'pointer' : 'default' }}
                >
                  <title>{`${agent.name} (ID: ${agent.id})\nIP: ${agent.ip}\nOS: ${agent.os || 'Unknown'}\nTipe: ${isRust ? 'Rust Agent (FIM+Active Response)' : 'Wazuh Agent'}\nStatus: ${agent.status}`}</title>

                  {/* Node Outer Ring */}
                  <circle
                    r="22"
                    fill={active ? '#F0FAF7' : '#FDF3F2'}
                    stroke={active ? '#00A389' : '#BD271E'}
                    strokeWidth="1.5"
                    strokeDasharray={active ? undefined : '4 3'}
                  />

                  {/* Node Inner Device Glyph */}
                  {isRust ? (
                    // Terminal glyph for Rust agent
                    <g transform="translate(-7, -7)">
                      <rect
                        x="0"
                        y="0"
                        width="14"
                        height="14"
                        rx="2"
                        fill="none"
                        stroke={active ? '#00A389' : '#BD271E'}
                        strokeWidth="1.2"
                      />
                      <path
                        d="M3 4.5 L6 7 L3 9.5"
                        fill="none"
                        stroke={active ? '#00A389' : '#BD271E'}
                        strokeWidth="1.2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                      <line
                        x1="7.5"
                        y1="9.5"
                        x2="11"
                        y2="9.5"
                        stroke={active ? '#00A389' : '#BD271E'}
                        strokeWidth="1.2"
                        strokeLinecap="round"
                      />
                    </g>
                  ) : isWin ? (
                    // Windows glyph
                    <g transform="translate(-6.5, -6.5)">
                      <rect
                        x="0"
                        y="0"
                        width="6"
                        height="6"
                        fill={active ? '#00A389' : '#BD271E'}
                        rx="0.5"
                      />
                      <rect
                        x="7"
                        y="0"
                        width="6"
                        height="6"
                        fill={active ? '#00A389' : '#BD271E'}
                        rx="0.5"
                      />
                      <rect
                        x="0"
                        y="7"
                        width="6"
                        height="6"
                        fill={active ? '#00A389' : '#BD271E'}
                        rx="0.5"
                      />
                      <rect
                        x="7"
                        y="7"
                        width="6"
                        height="6"
                        fill={active ? '#00A389' : '#BD271E'}
                        rx="0.5"
                      />
                    </g>
                  ) : (
                    // Standard Linux / Server display glyph
                    <g transform="translate(-7, -7)">
                      <rect
                        x="1"
                        y="1"
                        width="12"
                        height="9"
                        rx="1"
                        fill="none"
                        stroke={active ? '#00A389' : '#BD271E'}
                        strokeWidth="1.2"
                      />
                      <line
                        x1="4"
                        y1="13"
                        x2="10"
                        y2="13"
                        stroke={active ? '#00A389' : '#BD271E'}
                        strokeWidth="1.2"
                      />
                      <line
                        x1="7"
                        y1="10"
                        x2="7"
                        y2="13"
                        stroke={active ? '#00A389' : '#BD271E'}
                        strokeWidth="1.2"
                      />
                    </g>
                  )}

                  {/* Active/Offline Ping Indicator Dot */}
                  <circle
                    cx="15"
                    cy="-15"
                    r="4"
                    fill={active ? '#00A389' : '#BD271E'}
                    stroke="#FFFFFF"
                    strokeWidth="1.5"
                  />

                  {/* Hardware Label Box */}
                  <g transform="translate(0, 26)">
                    <rect
                      x="-54"
                      y="0"
                      width="108"
                      height="30"
                      rx="3"
                      fill="#FFFFFF"
                      stroke="#D3DAE6"
                      strokeWidth="1"
                    />
                    <text
                      y="12"
                      textAnchor="middle"
                      fontSize="9.5"
                      fontWeight="600"
                      fill="#1A1C21"
                    >
                      {displayName}
                    </text>
                    <text
                      y="23"
                      textAnchor="middle"
                      fontSize="8.5"
                      fill="#5A626F"
                      fontFamily="monospace"
                    >
                      {agent.ip || 'any'}
                    </text>
                  </g>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend Footer */}
        <div className="flex flex-wrap items-center justify-between border-t border-[#EBEFF5] pt-3 px-1 text-[11px] text-[#5A626F]">
          <div className="flex items-center gap-5">
            <span className="flex items-center gap-1.5">
              <span className="inline-block w-4 h-0.5 bg-[#00A389] rounded-full"></span> Active connection
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block w-4 h-0.5 bg-[#BD271E] border-b border-dashed border-[#BD271E]"></span> Disconnected
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block w-2.5 h-2.5 rounded bg-[#F0F5FA] border border-[#006BB4]"></span> SOAR Central Hub
            </span>
          </div>
          <span className="text-[#8A94A6]">Klik node endpoint untuk rincian inventaris &amp; FIM</span>
        </div>
      </div>
    </div>
  );
}
