'use client';

import React, { useMemo } from 'react';
import { Network } from 'lucide-react';
import type { FleetAgent } from '@/lib/fleet';

interface NetworkMapViewProps {
  agents: FleetAgent[];
  onSelectAgent?: (agentId: string) => void;
}

/** Heuristik laptop-vs-PC dari nama (fleet dikenal kecil; fallback = PC).
 *  ponytail: kalau fleet membesar / nama tak konsisten, ganti dengan field
 *  form_factor dari agent. */
function isLaptop(name: string): boolean {
  return /laptop|notebook|toshiba|asus|ideapc|bapak|handmade|book/i.test(name || '');
}

/** Ikon PC desktop (monitor + tower), terpusat di (0,0). */
function PcIcon({ dim }: { dim: boolean }) {
  return (
    <g opacity={dim ? 0.45 : 1} transform="translate(-2,-16)">
      <rect x={12} y={0} width="13" height="32" rx="1.5" fill="#D3DAE6" stroke="#5A626F" strokeWidth="1.5" />
      <rect x={14.5} y={4} width="8" height="3" fill="#00A389" />
      <rect x={-20} y={0} width="30" height="24" rx="2" fill="#E8EEF4" stroke="#5A626F" strokeWidth="1.5" />
      <rect x={-17} y={3} width="24" height="18" fill="#BDD7EE" />
      <line x1={-5} y1={24} x2={-5} y2={30} stroke="#5A626F" strokeWidth="2" />
      <line x1={-12} y1={30} x2={2} y2={30} stroke="#5A626F" strokeWidth="2" />
    </g>
  );
}

/** Ikon laptop (layar + base), terpusat di (0,0). */
function LaptopIcon({ dim }: { dim: boolean }) {
  return (
    <g opacity={dim ? 0.45 : 1} transform="translate(1,-13)">
      <rect x={-16} y={0} width="30" height="21" rx="2" fill="#E8EEF4" stroke="#5A626F" strokeWidth="1.5" />
      <rect x={-13} y={3} width="24" height="15" fill="#BDD7EE" />
      <polygon points="-20,21 18,21 22,27 -24,27" fill="#D3DAE6" stroke="#5A626F" strokeWidth="1.5" />
    </g>
  );
}

/** Peta jaringan hub-and-spoke ala kartu Wazuh: server di tengah, agent di
 *  sekeliling sebagai ikon PC/laptop (bukan lingkaran). Garis hijau = active,
 *  merah = disconnected. Klik node = detail agent. */
export function NetworkMapView({ agents, onSelectAgent }: NetworkMapViewProps) {
  const W = 640;
  const H = 400;
  const cx = W / 2;
  const cy = H / 2;

  // fetchSnapshot() sudah menyaring 000 wazuh.manager (server itu sendiri),
  // jadi di sini semua agents = endpoint spoke.
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
            <rect x={cx - 70} y={cy - 22} width="140" height="44" rx="8" fill="#fff" stroke="#006BB4" strokeWidth="1.5" />
            <text x={cx} y={cy - 2} textAnchor="middle" fill="#1A1C21" fontSize="12" fontWeight="bold">
              SOAR server
            </text>
            <text x={cx} y={cy + 14} textAnchor="middle" fill="#5A626F" fontSize="10" fontFamily="monospace">
              n8n + fleet + wazuh
            </text>
          </g>
          {/* Agent nodes */}
          {nodes.map(({ agent, x, y, active }) => (
            <g
              key={agent.id}
              transform={`translate(${x},${y})`}
              onClick={() => onSelectAgent?.(agent.id)}
              style={{ cursor: onSelectAgent ? 'pointer' : 'default' }}
            >
              <title>{`${agent.name} (${agent.ip}) — ${agent.status || 'unknown'}${agent.os && agent.os !== 'unknown' ? ` — ${agent.os}` : ''}`}</title>
              <circle r="24" fill={active ? '#EBF7F3' : '#FDECEA'} opacity="0.6" />
              <circle
                r="24"
                fill="none"
                stroke={active ? '#00A389' : '#BD271E'}
                strokeWidth="1.5"
                strokeDasharray={active ? undefined : '4 3'}
              />
              {isLaptop(agent.name) ? <LaptopIcon dim={!active} /> : <PcIcon dim={!active} />}
              <text y={38} textAnchor="middle" fontSize="11" fontWeight="600" fill="#1A1C21">
                {agent.name}
              </text>
              <text y={51} textAnchor="middle" fontSize="9" fill="#5A626F" fontFamily="monospace">
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
