'use client';

import React from 'react';
import { Maximize2, Radio, FileText } from 'lucide-react';
import { WazuhFilterBar } from './WazuhFilterBar';

export function VulnerabilitiesDashboard() {
  return (
    <div className="space-y-4">
      {/* Sub-tabs */}
      <div className="flex items-center justify-between border-b border-[#D3DAE6] pb-2">
        <div className="flex items-center gap-6 text-[13px]">
          <button className="font-medium pb-2.5 -mb-2 text-[#5A626F] hover:text-[#1A1C21]">
            Inventory
          </button>
          <button className="font-medium pb-2.5 -mb-2 border-b-2 border-[#006BB4] text-[#006BB4]">
            Dashboard
          </button>
          <button className="font-medium pb-2.5 -mb-2 text-[#5A626F] hover:text-[#1A1C21]">
            Events
          </button>
        </div>

        <div className="flex items-center gap-4 text-[12px]">
          <button className="flex items-center gap-1.5 text-[#006BB4] hover:underline font-medium">
            <Radio className="w-3.5 h-3.5" />
            <span>Explore agent</span>
          </button>
          <button className="flex items-center gap-1.5 text-[#006BB4] hover:underline font-medium">
            <FileText className="w-3.5 h-3.5" />
            <span>Generate report</span>
          </button>
        </div>
      </div>

      <WazuhFilterBar initialFilters={['cluster.name: wazuh', 'rule.groups: vulnerability-detector']} />

      {/* 4 Severity Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Critical Severity Alerts</div>
          <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">450</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">High Severity Alerts</div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">725</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Medium Severity Alerts</div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">1,260</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Low Severity Alerts</div>
          <div className="text-[32px] font-semibold text-[#64748B] leading-tight mt-1">565</div>
        </div>
      </div>

      {/* Row 1 Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Most affected agents */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Most affected agents</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

          <div className="flex items-center justify-center gap-6 h-52">
            <div className="relative w-36 h-36 flex items-center justify-center">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <circle cx="50" cy="50" r="38" fill="none" stroke="#D9381E" strokeWidth="16" strokeDasharray="80 160" strokeDashoffset="0" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#00A389" strokeWidth="16" strokeDasharray="70 170" strokeDashoffset="-80" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#006BB4" strokeWidth="16" strokeDasharray="40 200" strokeDashoffset="-150" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#9B51E0" strokeWidth="16" strokeDasharray="30 210" strokeDashoffset="-190" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#E2B93B" strokeWidth="16" strokeDasharray="20 220" strokeDashoffset="-220" />
              </svg>
            </div>

            <div className="text-[11px] space-y-1.5 text-[#5A626F]">
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#D9381E]"></span><span>.Net server</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#00A389]"></span><span>Ubuntu</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#006BB4]"></span><span>Centos</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#9B51E0]"></span><span>Debian</span></div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-[#E2B93B]"></span><span>Windows</span></div>
            </div>
          </div>
        </div>

        {/* Alerts severity area chart */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Alerts severity</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

          <div className="flex items-center justify-between gap-4 h-52">
            <div className="flex-1 h-full flex flex-col justify-end">
              <svg viewBox="0 0 400 140" className="w-full h-full overflow-visible">
                <path d="M0,80 Q50,40 100,60 T200,50 T300,70 T400,60 L400,130 L0,130 Z" fill="#9B51E0" fillOpacity="0.7" />
                <path d="M0,100 Q50,70 100,85 T200,80 T300,95 T400,90 L400,130 L0,130 Z" fill="#00A389" fillOpacity="0.8" />
                <line x1="0" y1="130" x2="400" y2="130" stroke="#D3DAE6" strokeWidth="1" />
              </svg>
              <div className="flex justify-between text-[10px] text-[#8A94A6] mt-2">
                <span>2026-01-18 00:00</span>
                <span>2026-01-21 00:00</span>
                <span>2026-01-24 00:00</span>
              </div>
            </div>

            <div className="w-20 text-[11px] space-y-1.5 text-[#5A626F] shrink-0 border-l border-[#EBEFF5] pl-3">
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#00A389]"></span><span>High</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#BD271E]"></span><span>Critical</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#9B51E0]"></span><span>Medium</span></div>
              <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#E2557B]"></span><span>Low</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: Most common CVEs & CWEs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Most common CVEs */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Most common CVEs</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

          <div className="flex items-center justify-center gap-4 h-48">
            <div className="relative w-28 h-28 flex items-center justify-center">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <circle cx="50" cy="50" r="38" fill="none" stroke="#00A389" strokeWidth="16" strokeDasharray="100 140" strokeDashoffset="0" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#006BB4" strokeWidth="16" strokeDasharray="80 160" strokeDashoffset="-100" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#E67E22" strokeWidth="16" strokeDasharray="40 200" strokeDashoffset="-180" />
              </svg>
            </div>
            <div className="text-[10px] space-y-1 text-[#5A626F]">
              <div>CVE-2020-1927</div>
              <div>CVE-2013-4235</div>
              <div>CVE-2018-7738</div>
              <div>CVE-2020-1752</div>
            </div>
          </div>
        </div>

        {/* Affected packages evolution */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">TOP affected packages</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>
          <div className="h-48 flex items-end justify-between gap-1 border-b border-[#D3DAE6] pb-1">
            {Array.from({ length: 16 }).map((_, i) => (
              <div key={i} className="flex-1 flex flex-col justify-end h-full">
                <div style={{ height: `${20 + (i % 4) * 15}%` }} className="bg-[#006BB4] w-full"></div>
                <div style={{ height: `${15 + (i % 3) * 10}%` }} className="bg-[#00A389] w-full"></div>
                <div style={{ height: `${10 + (i % 5) * 8}%` }} className="bg-[#BD271E] w-full"></div>
              </div>
            ))}
          </div>
        </div>

        {/* Most common CWEs */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[13px] font-semibold text-[#1A1C21]">Most common CWEs</div>
            <Maximize2 className="w-3.5 h-3.5 text-[#8A94A6]" />
          </div>

          <div className="flex items-center justify-center gap-4 h-48">
            <div className="relative w-28 h-28 flex items-center justify-center">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <circle cx="50" cy="50" r="38" fill="none" stroke="#E2557B" strokeWidth="16" strokeDasharray="90 150" strokeDashoffset="0" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#00A389" strokeWidth="16" strokeDasharray="70 170" strokeDashoffset="-90" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#006BB4" strokeWidth="16" strokeDasharray="40 200" strokeDashoffset="-160" />
              </svg>
            </div>
            <div className="text-[10px] space-y-1 text-[#5A626F]">
              <div>CWE-125</div>
              <div>CWE-601</div>
              <div>CWE-119</div>
              <div>CWE-120</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
