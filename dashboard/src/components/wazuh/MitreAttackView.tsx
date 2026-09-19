'use client';

import React from 'react';
import { Grid, ShieldAlert, ShieldCheck } from 'lucide-react';

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
    playbook: 'Active Response — Quarantine',
    phase: 'Impact',
    techniques: [
      { id: 'T1070.004', name: 'File Deletion (remediasi)', count: 1 },
    ],
  },
  {
    playbook: 'Active Response — Block Domain',
    phase: 'Initial Access → Impact',
    techniques: [{ id: 'T1484', name: 'Domain Policy Modification', count: 3 }],
  },
  {
    playbook: 'Health Monitor',
    phase: 'Impact (availability)',
    techniques: [{ id: 'T1499', name: 'Endpoint DoS (monitoring)', count: 1 }],
  },
];

export function MitreAttackView() {
  const totalTech = new Set(
    PLAYBOOK_MAP.flatMap((p) => p.techniques.map((t) => t.id))
  ).size;

  return (
    <div className="space-y-4">
      {/* KPI */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Playbook dipetakan</div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">
            {PLAYBOOK_MAP.length}
          </div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Teknik unik</div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">{totalTech}</div>
        </div>
        <div>
          <div className="text-[12px] text-[#5A626F] font-medium">Fase tercover</div>
          <div className="text-[32px] font-semibold text-[#64748B] leading-tight mt-1">4</div>
        </div>
      </div>

      {/* Coverage note */}
      <div className="flex items-start gap-2 bg-white border border-[#D3DAE6] rounded px-4 py-3 text-[12px] text-[#5A626F]">
        <Grid className="w-4 h-4 text-[#006BB4] shrink-0 mt-0.5" />
        <div>
          Pemetaan teknik MITRE ATT&amp;CK ke playbook n8n. Coverage snapshot sesuai{' '}
          <code className="text-[#BD271E]">docs/MITRE-ATTACK-MAPPING.md</code>.
          Bullet = jumlah playbook yang menyinggung teknik tersebut.
        </div>
      </div>

      {/* Render per playbook */}
      {PLAYBOOK_MAP.map((pb) => (
        <div key={pb.playbook} className="bg-white border border-[#D3DAE6] rounded">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#D3DAE6]">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[#006BB4]" />
              <h2 className="text-[14px] font-semibold">{pb.playbook}</h2>
            </div>
            <span className="text-[11px] text-[#8A94A6]">{pb.phase}</span>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
            {pb.techniques.map((t) => (
              <div
                key={t.id}
                className="border border-[#EDEEF2] rounded p-3 flex items-start gap-3"
              >
                <div className="mt-0.5 p-2 rounded bg-[#F5F7FA] text-[#006BB4] shrink-0">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[12px] font-semibold text-[#1A1C21]">{t.id}</span>
                    <span className="text-[11px] font-bold text-[#006BB4]">
                      {'●'.repeat(Math.min(t.count, 3))}
                    </span>
                  </div>
                  <div className="text-[12px] text-[#5A626F] mt-0.5">{t.name}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
