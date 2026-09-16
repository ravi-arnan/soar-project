'use client';

import React, { useMemo } from 'react';
import { Network } from 'lucide-react';
import type { FleetAgent } from '@/lib/fleet';

interface NetworkMapViewProps {
  agents: FleetAgent[];
  onSelectAgent?: (agentId: string) => void;
}

/** Peta jaringan hub-and-spoke (SVG native): server di tengah, agent di sekeliling.
 *  Garis hijau = active, merah = disconnected. Klik node = detail agent. */
export function NetworkMapView({ agents, onSelectAgent }: NetworkMapViewProps) {
  const W = 640;
  const H = 400;
  const cx = W / 2;
  const cy = H / 2;

  const nodes = useMemo(() => {
    const n = agents.length || 1;
    const rx = W / 2 - 90;
    const ry = H / 2 - 70;
    return agents.map((a, i) => {
      const ang = (2 * Math.PI * i) / n - Math.PI / 2;
      return {
        agent: a,
        x: cx + rx * Math.cos(ang),
        y: cy + ry * Math.sin(ang),
        active: (a.status || '').toLowerCase() === 'active',
      };
    });
  }, [agents]);

  const activeCount = nodes.filter((d) => d.active).length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Node fleet</div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">{agents.length + 1}</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Agent active</div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">{activeCount}</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Disconnected</div>
          <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">{nodes.length - activeCount}</div>
        </div>
      </div>

      <div className="bg-white border border-[#D3DAE6] rounded p-4">
        <div className="flex items-center gap-2 px-1 pb-3">
          <Network className="w-4 h-4 text-[#006BB4]" />
          <h2 className="text-[14px] font-semibold">Topologi fleet (hub-and-spoke)</h2>
        </div>
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full max-h-[420px]">
          {nodes.map(({ agent, x, y, active }) => (
            <line
              key={`e-${agent.id}`}
              x1={cx}
              y1={cy}
              x2={x}
              y2={y}
              stroke={active ? '#00A389' : '#BD271E'}
              strokeWidth="1.5"
              strokeDasharray={active ? undefined : '5 4'}
              opacity="0.7"
            />
          ))}
          {/* Server hub */}
          <g>
            <rect x={cx - 70} y={cy - 22} width="140" height="44" rx="8" fill="#011a2f" />
            <text x={cx} y={cy - 2} textAnchor="middle" fill="#fff" fontSize="12" fontWeight="bold">
              SOAR server
            </text>
            <text x={cx} y={cy + 14} textAnchor="middle" fill="#00a9e0" fontSize="10" fontFamily="monospace">
              n8n + fleet + wazuh
            </text>
          </g>
          {/* Agent nodes */}
          {nodes.map(({ agent, x, y, active }) => (
            <g
              key={agent.id}
              onClick={() => onSelectAgent?.(agent.id)}
              style={{ cursor: onSelectAgent ? 'pointer' : 'default' }}
            >
              <circle
                cx={x}
                cy={y}
                r="20"
                fill={active ? '#EBF7F3' : '#FDECEA'}
                stroke={active ? '#00A389' : '#BD271E'}
                strokeWidth="2"
              />
              <circle cx={x} cy={y} r="5" fill={active ? '#00A389' : '#BD271E'} />
              <text x={x} y={y + 34} textAnchor="middle" fontSize="11" fontWeight="600" fill="#1A1C21">
                {agent.name}
              </text>
              <text x={x} y={y + 47} textAnchor="middle" fontSize="9" fill="#5A626F" fontFamily="monospace">
                {agent.ip}
              </text>
            </g>
          ))}
        </svg>
        <div className="flex items-center gap-4 mt-2 text-[11px] text-[#5A626F] px-1">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-6 h-0.5 bg-[#00A389]"></span> active
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-6 h-0.5 bg-[#BD271E]"></span> disconnected
          </span>
          <span className="ml-auto">klik node untuk detail agent</span>
        </div>
      </div>
    </div>
  );
}
