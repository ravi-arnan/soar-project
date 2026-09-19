'use client';

import React from 'react';
import { CheckCircle2, XCircle, Server, Webhook, Database } from 'lucide-react';
import type { FleetHealth, FleetStats } from '@/lib/fleet';
import { formatWazuhTime } from '@/lib/fleet';

interface SettingsViewProps {
  health?: FleetHealth;
  stats: FleetStats;
  generatedAt: string;
  online: boolean;
}

function StatusRow({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-[#EDEEF2] last:border-0">
      <div className="flex items-center gap-2.5">
        {ok ? (
          <CheckCircle2 className="w-4 h-4 text-[#00A389]" />
        ) : (
          <XCircle className="w-4 h-4 text-[#BD271E]" />
        )}
        <span className="text-[13px] font-medium">{label}</span>
      </div>
      <span className="text-[12px] text-[#5A626F]">{detail}</span>
    </div>
  );
}

export function SettingsView({ health, stats, generatedAt, online }: SettingsViewProps) {
  const endpoints = [
    { method: 'GET', path: '/api/fleet', desc: 'Status agent + kesehatan stack' },
    { method: 'GET', path: '/api/events', desc: 'Threat events untuk dashboard' },
    { method: 'POST', path: '/webhook-log', desc: 'Node n8n Log ke Fleet menulis verdict ke sini' },
    { method: 'POST', path: ':5678/webhook/wazuh-alert', desc: 'Webhook n8n Deteksi Malware' },
    { method: 'POST', path: ':5678/webhook/wazuh-phishing', desc: 'Webhook n8n Deteksi Phishing' },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Stack status */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center gap-2 mb-2">
            <Server className="w-4 h-4 text-[#006BB4]" />
            <h2 className="text-[14px] font-semibold">Stack status</h2>
          </div>
          <StatusRow ok={!!health?.n8n} label="n8n" detail="Orkestrasi workflow SOAR" />
          <StatusRow ok={!!health?.gemini} label="AI analysis" detail="LLM untuk Analisis AI Telegram" />
          <StatusRow ok={!!health?.wazuh_api} label="Wazuh API" detail="Active response + query agent" />
        </div>

        {/* Data status */}
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="flex items-center gap-2 mb-2">
            <Database className="w-4 h-4 text-[#006BB4]" />
            <h2 className="text-[14px] font-semibold">Data status</h2>
          </div>
          <StatusRow ok={online} label="Backend fleet" detail={online ? 'Terjangkau' : 'Tidak terjangkau'} />
          <StatusRow
            ok={stats.active > 0}
            label="Agent aktif"
            detail={`${stats.active}/${stats.total} endpoint (${stats.rust} Rust agent)`}
          />
          <StatusRow ok={true} label="Event tercatat" detail={`${stats.events_total} event`} />
          <div className="pt-2 text-[12px] text-[#5A626F]">
            Update terakhir: {generatedAt ? formatWazuhTime(generatedAt) : '-'}
          </div>
        </div>
      </div>

      {/* Endpoints */}
      <div className="bg-white border border-[#D3DAE6] rounded p-4">
        <div className="flex items-center gap-2 mb-2">
          <Webhook className="w-4 h-4 text-[#006BB4]" />
          <h2 className="text-[14px] font-semibold">Backend endpoints</h2>
        </div>
        <div className="text-[12px] text-[#5A626F] mb-2">
          Dashboard rewrite <code className="bg-[#F0F4F8] px-1 rounded">/api/*</code> ke fleet-monitor
          <code className="bg-[#F0F4F8] px-1 rounded">:8080</code>. Webhook n8n di
          <code className="bg-[#F0F4F8] px-1 rounded">:5678</code>.
        </div>
        {endpoints.map((e) => (
          <div
            key={e.method + e.path}
            className="flex items-center gap-3 py-2 border-b border-[#EDEEF2] last:border-0 text-[13px]"
          >
            <span
              className={`font-mono text-[11px] font-bold px-1.5 py-0.5 rounded ${
                e.method === 'GET' ? 'bg-[#EBF5FB] text-[#006BB4]' : 'bg-[#FEF3E8] text-[#B25E09]'
              }`}
            >
              {e.method}
            </span>
            <code className="font-mono text-[12px]">{e.path}</code>
            <span className="text-[12px] text-[#5A626F] ml-auto text-right">{e.desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
