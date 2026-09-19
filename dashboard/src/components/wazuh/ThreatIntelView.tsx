'use client';

import React, { useMemo } from 'react';
import { ShieldAlert, Fingerprint, AlertTriangle } from 'lucide-react';
import type { FleetEvent } from '@/lib/fleet';
import { formatWazuhTime } from '@/lib/fleet';

interface ThreatIntelViewProps {
  events: FleetEvent[];
}

export function ThreatIntelView({ events }: ThreatIntelViewProps) {
  const intel = useMemo(() => {
    const withHash = events.filter((e) => e.hash);
    const crit = withHash.filter((e) => e.severity === 'CRITICAL').length;
    const high = withHash.filter((e) => e.severity === 'HIGH').length;
    const uniq = new Set(withHash.map((e) => e.hash)).size;
    const recent = [...withHash]
      .sort((a, b) => (a.ts < b.ts ? 1 : -1))
      .slice(0, 20);
    return { total: withHash.length, crit, high, uniq, recent };
  }, [events]);

  return (
    <div className="space-y-4">
      {/* Ringkasan verdict pipeline */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">File terverifikasi intel</div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">{intel.total}</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">CRITICAL</div>
          <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">{intel.crit}</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">HIGH</div>
          <div className="text-[32px] font-semibold text-[#B25E09] leading-tight mt-1">{intel.high}</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Hash unik</div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">{intel.uniq}</div>
        </div>
      </div>

      {/* Daftar hash terbaru */}
      <div className="bg-white border border-[#D3DAE6] rounded">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-[#D3DAE6]">
          <Fingerprint className="w-4 h-4 text-[#006BB4]" />
          <h2 className="text-[14px] font-semibold">Hash terbaru dari pipeline</h2>
        </div>
        {intel.recent.length === 0 ? (
          <div className="flex items-center gap-2 px-4 py-6 text-[13px] text-[#5A626F]">
            <ShieldAlert className="w-4 h-4" />
            Belum ada file yang melewati threat intel.
          </div>
        ) : (
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-[#8A94A6] border-b border-[#D3DAE6]">
                <th className="px-4 py-2 font-semibold">Hash</th>
                <th className="px-4 py-2 font-semibold">Agent</th>
                <th className="px-4 py-2 font-semibold">Severity</th>
                <th className="px-4 py-2 font-semibold">Waktu</th>
              </tr>
            </thead>
            <tbody>
              {intel.recent.map((e, i) => (
                <tr key={`${e.hash}-${e.ts}-${i}`} className="border-b border-[#EDEEF2] last:border-0">
                  <td className="px-4 py-2 font-mono text-[12px]" title={`${e.hash} (klik untuk buka di VirusTotal)`}>
                    <a
                      href={`https://www.virustotal.com/gui/file/${e.hash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[#006BB4] hover:underline"
                    >
                      {e.hash.slice(0, 16)}...
                    </a>
                  </td>
                  <td className="px-4 py-2">{e.agent}</td>
                  <td className="px-4 py-2">
                    <span
                      className={`inline-flex items-center gap-1 text-[11px] font-semibold px-1.5 py-0.5 rounded ${
                        e.severity === 'CRITICAL'
                          ? 'bg-[#FDECEA] text-[#BD271E]'
                          : e.severity === 'HIGH'
                            ? 'bg-[#FEF3E8] text-[#B25E09]'
                            : 'bg-[#F0F4F8] text-[#5A626F]'
                      }`}
                    >
                      {e.severity === 'CRITICAL' && <AlertTriangle className="w-3 h-3" />}
                      {e.severity || 'UNKNOWN'}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-[#5A626F]">{formatWazuhTime(e.ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="px-4 py-2.5 text-[12px] text-[#5A626F] border-t border-[#D3DAE6]">
          Verdict gabungan VirusTotal + OTX via workflow n8n. Rincian VT (malicious/total) ada di notifikasi
          Telegram tiap alert.
        </div>
      </div>
    </div>
  );
}
