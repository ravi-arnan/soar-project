'use client';

import React, { useState } from 'react';
import { Grid, ShieldAlert, ShieldCheck, LayoutGrid, ListFilter } from 'lucide-react';

interface TechniqueItem {
  id: string;
  name: string;
  count: number;
  playbooks: string[];
}

interface TacticColumn {
  id: string;
  name: string;
  techniques: TechniqueItem[];
}

const TACTICS_MATRIX: TacticColumn[] = [
  {
    id: 'TA0001',
    name: 'Initial Access',
    techniques: [
      {
        id: 'T1566.002',
        name: 'Spearphishing Link',
        count: 5,
        playbooks: ['Deteksi Phishing', 'Proaktif Phishing'],
      },
      {
        id: 'T1189',
        name: 'Drive-by Compromise',
        count: 2,
        playbooks: ['Deteksi Phishing'],
      },
      {
        id: 'T1566',
        name: 'Phishing via Dokumen',
        count: 1,
        playbooks: ['Deteksi LOLBin Chain'],
      },
    ],
  },
  {
    id: 'TA0002',
    name: 'Execution',
    techniques: [
      {
        id: 'T1204.002',
        name: 'User Execution: Malicious File',
        count: 2,
        playbooks: ['Deteksi Malware'],
      },
      {
        id: 'T1059.001',
        name: 'PowerShell Interpreter',
        count: 3,
        playbooks: ['Deteksi LOLBin Chain'],
      },
      {
        id: 'T1059.006',
        name: 'Python Interpreter',
        count: 1,
        playbooks: ['Deteksi LOLBin Chain'],
      },
      {
        id: 'T1059',
        name: 'Command & Script Interpreter',
        count: 3,
        playbooks: ['Deteksi Malware', 'Deteksi LOLBin Chain'],
      },
    ],
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    techniques: [
      {
        id: 'T1027',
        name: 'Obfuscated Files or Info',
        count: 1,
        playbooks: ['Deteksi Malware'],
      },
      {
        id: 'T1036',
        name: 'Masquerading',
        count: 3,
        playbooks: ['Deteksi Malware', 'Deteksi LOLBin Chain'],
      },
      {
        id: 'T1218.010',
        name: 'Signed Binary: Regsvr32',
        count: 1,
        playbooks: ['Deteksi LOLBin Chain'],
      },
      {
        id: 'T1218.011',
        name: 'Signed Binary: Rundll32',
        count: 1,
        playbooks: ['Deteksi LOLBin Chain'],
      },
    ],
  },
  {
    id: 'TA0040',
    name: 'Impact & Remediation',
    techniques: [
      {
        id: 'T1070.004',
        name: 'File Deletion (Remediasi)',
        count: 1,
        playbooks: ['Active Response - Quarantine'],
      },
      {
        id: 'T1484',
        name: 'Domain Policy (Sinkhole)',
        count: 3,
        playbooks: ['Active Response - Block Domain'],
      },
      {
        id: 'T1499',
        name: 'Endpoint DoS (Monitoring)',
        count: 1,
        playbooks: ['Health Monitor'],
      },
    ],
  },
];

const PLAYBOOK_MAP: Array<{
  playbook: string;
  phase: string;
  techniques: Array<{ id: string; name: string; count: number }>;
}> = [
  {
    playbook: 'Deteksi Malware (FIM + VT)',
    phase: 'Execution, Defense Evasion, Initial Access',
    techniques: [
      { id: 'T1204.002', name: 'User Execution: Malicious File', count: 2 },
      { id: 'T1059', name: 'Command and Scripting Interpreter', count: 1 },
      { id: 'T1027', name: 'Obfuscated Files or Information', count: 1 },
      { id: 'T1036', name: 'Masquerading', count: 2 },
    ],
  },
  {
    playbook: 'Deteksi Phishing (URL + GSB/URLScan)',
    phase: 'Initial Access',
    techniques: [
      { id: 'T1566.002', name: 'Spearphishing Link', count: 2 },
      { id: 'T1189', name: 'Drive-by Compromise', count: 2 },
    ],
  },
  {
    playbook: 'Proaktif Phishing (URLhaus feed)',
    phase: 'Initial Access (preventif)',
    techniques: [{ id: 'T1566.002', name: 'Spearphishing Link', count: 3 }],
  },
  {
    playbook: 'Deteksi LOLBin Chain (Sysmon)',
    phase: 'Execution, Defense Evasion',
    techniques: [
      { id: 'T1059.001', name: 'PowerShell (110001-110003)', count: 3 },
      { id: 'T1059.006', name: 'Python (110003)', count: 1 },
      { id: 'T1059', name: 'Script interpreter (110004, 110008)', count: 2 },
      { id: 'T1218.010', name: 'Regsvr32 (110007)', count: 1 },
      { id: 'T1218.011', name: 'Rundll32 (110007)', count: 1 },
      { id: 'T1036', name: 'Masquerading (110005)', count: 1 },
      { id: 'T1566', name: 'Phishing via dokumen (110006)', count: 1 },
    ],
  },
  {
    playbook: 'Active Response - Quarantine',
    phase: 'Impact',
    techniques: [
      { id: 'T1070.004', name: 'File Deletion (remediasi)', count: 1 },
    ],
  },
  {
    playbook: 'Active Response - Block Domain',
    phase: 'Initial Access -> Impact',
    techniques: [{ id: 'T1484', name: 'Domain Policy Modification', count: 3 }],
  },
  {
    playbook: 'Health Monitor',
    phase: 'Impact (availability)',
    techniques: [{ id: 'T1499', name: 'Endpoint DoS (monitoring)', count: 1 }],
  },
];

export function MitreAttackView() {
  const [activeTab, setActiveTab] = useState<'matrix' | 'playbooks'>('matrix');

  const totalTech = new Set(
    PLAYBOOK_MAP.flatMap((p) => p.techniques.map((t) => t.id))
  ).size;

  return (
    <div className="space-y-4">
      {/* KPI Header Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Playbook dipetakan</div>
          <div className="text-[32px] font-semibold text-[#006BB4] font-mono tabular-nums leading-tight mt-1">
            {PLAYBOOK_MAP.length}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">Workflow teruji n8n</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Teknik unik</div>
          <div className="text-[32px] font-semibold text-[#00A389] font-mono tabular-nums leading-tight mt-1">
            {totalTech}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">Matrix v14.1 enterprise</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Taktik tercover</div>
          <div className="text-[32px] font-semibold text-[#1A1C21] font-mono tabular-nums leading-tight mt-1">
            {TACTICS_MATRIX.length}
          </div>
          <div className="text-[11px] text-[#8A94A6] mt-0.5">Fase rantai serangan</div>
        </div>
      </div>

      {/* Subheader Toolbar & View Switcher */}
      <div className="bg-white border border-[#D3DAE6] rounded px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-[12px]">
        <div className="flex items-center gap-2">
          <Grid className="w-4 h-4 text-[#006BB4]" />
          <span className="font-semibold text-[#1A1C21]">
            MITRE ATT&amp;CK Framework Navigator
          </span>
          <span className="text-[#8A94A6] text-[11px]">
            (Kesesuaian dengan Dokumen Ilmiah TA)
          </span>
        </div>

        <div className="inline-flex rounded border border-[#D3DAE6] bg-[#F8FAFC] p-0.5">
          <button
            type="button"
            onClick={() => setActiveTab('matrix')}
            className={`px-3 py-1 rounded text-[11px] font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
              activeTab === 'matrix'
                ? 'bg-white text-[#1A1C21] font-semibold shadow-2xs border border-[#D3DAE6]'
                : 'text-[#5A626F] hover:text-[#1A1C21]'
            }`}
          >
            <LayoutGrid className="w-3.5 h-3.5 text-[#006BB4]" />
            <span>Enterprise Matrix Grid</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('playbooks')}
            className={`px-3 py-1 rounded text-[11px] font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
              activeTab === 'playbooks'
                ? 'bg-white text-[#1A1C21] font-semibold shadow-2xs border border-[#D3DAE6]'
                : 'text-[#5A626F] hover:text-[#1A1C21]'
            }`}
          >
            <ListFilter className="w-3.5 h-3.5 text-[#00A389]" />
            <span>Playbook Pipeline View</span>
          </button>
        </div>
      </div>

      {/* VIEW 1: Enterprise Matrix Grid */}
      {activeTab === 'matrix' && (
        <div className="bg-white border border-[#D3DAE6] rounded p-4 overflow-x-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 min-w-[800px]">
            {TACTICS_MATRIX.map((tac) => (
              <div
                key={tac.id}
                className="border border-[#E2E8F0] rounded bg-[#FAFBFD] overflow-hidden flex flex-col"
              >
                {/* Tactic Column Header */}
                <div className="bg-[#F0F5FA] border-b border-[#D3DAE6] px-3.5 py-2.5">
                  <div className="text-[10px] font-mono font-bold text-[#006BB4]">
                    {tac.id}
                  </div>
                  <div className="text-[12px] font-bold text-[#1A1C21] truncate">
                    {tac.name}
                  </div>
                  <div className="text-[10px] text-[#8A94A6] font-mono mt-0.5">
                    {tac.techniques.length} teknik aktif
                  </div>
                </div>

                {/* Techniques Stack */}
                <div className="p-2.5 space-y-2 flex-1">
                  {tac.techniques.map((t) => (
                    <div
                      key={t.id}
                      className="bg-white border border-[#D3DAE6] rounded p-2.5 hover:border-[#006BB4] hover:shadow-xs transition-all"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-mono text-[11px] font-bold text-[#006BB4]">
                          {t.id}
                        </span>
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold font-mono bg-[#EBF5FB] text-[#006BB4]">
                          {t.count}x
                        </span>
                      </div>
                      <div className="text-[11px] font-semibold text-[#1A1C21] mt-1 leading-snug">
                        {t.name}
                      </div>
                      <div className="mt-2 pt-1.5 border-t border-[#F0F4F8] flex flex-wrap gap-1">
                        {t.playbooks.map((pb) => (
                          <span
                            key={pb}
                            className="text-[9.5px] px-1 py-0.5 rounded bg-[#F5F7FA] text-[#5A626F] border border-[#EBEFF5]"
                          >
                            {pb}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between border-t border-[#EBEFF5] mt-4 pt-3 text-[11px] text-[#5A626F]">
            <span>Heatmap intensitas didasarkan pada jumlah playbook yang mengimplementasikan deteksi.</span>
            <span className="text-[#8A94A6] font-mono">MITRE ATT&amp;CK v14.1 Enterprise Matrix</span>
          </div>
        </div>
      )}

      {/* VIEW 2: Playbook Pipeline View */}
      {activeTab === 'playbooks' && (
        <div className="space-y-3">
          {PLAYBOOK_MAP.map((pb) => (
            <div key={pb.playbook} className="bg-white border border-[#D3DAE6] rounded overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2.5 bg-[#FAFBFD] border-b border-[#EBEFF5]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-[#006BB4]" />
                  <h2 className="text-[13px] font-bold text-[#1A1C21]">{pb.playbook}</h2>
                </div>
                <span className="text-[11px] font-mono text-[#8A94A6]">{pb.phase}</span>
              </div>
              <div className="p-3.5 grid grid-cols-1 md:grid-cols-2 gap-3">
                {pb.techniques.map((t) => (
                  <div
                    key={t.id}
                    className="border border-[#E2E8F0] rounded p-3 flex items-start gap-3 bg-white"
                  >
                    <div className="mt-0.5 p-2 rounded bg-[#F0F5FA] text-[#006BB4] shrink-0 border border-[#E0ECF6]">
                      <ShieldAlert className="w-4 h-4" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-mono text-[12px] font-bold text-[#1A1C21]">{t.id}</span>
                        <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-[#EBF5FB] text-[#006BB4]">
                          {t.count} aturan
                        </span>
                      </div>
                      <div className="text-[12px] text-[#5A626F] mt-0.5 leading-snug">{t.name}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
