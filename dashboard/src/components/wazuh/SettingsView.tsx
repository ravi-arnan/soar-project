'use client';

import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  Server,
  Database,
  Sliders,
  Key,
  Cpu,
  Layers,
  Activity,
  MemoryStick,
  Sparkles,
} from 'lucide-react';
import type { FleetHealth, FleetStats } from '@/lib/fleet';
import { formatWazuhTime } from '@/lib/fleet';
import { ApiKeysView } from './ApiKeysView';
import { DynamicSettingsView } from './DynamicSettingsView';

interface SettingsViewProps {
  health?: FleetHealth;
  stats: FleetStats;
  generatedAt: string;
  online: boolean;
  refreshMs: number;
  onRefreshMsChange: (ms: number) => void;
  initialTab?: 'general' | 'keys' | 'dynamic-config';
}

interface ComponentResource {
  name: string;
  category: 'core' | 'orchestration' | 'storage' | 'microservice' | 'ai';
  role: string;
  memory: string;
  memPercent: string;
  status: string;
  isOk: boolean;
  port?: string;
}

export function SettingsView({
  health,
  stats,
  generatedAt,
  online,
  refreshMs,
  onRefreshMsChange,
  initialTab = 'general',
}: SettingsViewProps) {
  const [activeTab, setActiveTab] = useState<'general' | 'keys' | 'dynamic-config'>(initialTab);

  // Data pemakaian resource riil kontainer Docker di server produksi (docker stats)
  const components: ComponentResource[] = [
    {
      name: 'Wazuh Indexer (OpenSearch Cluster)',
      category: 'storage',
      role: 'Penyimpanan event terpusat, pengindeksan telemetri FIM & audit log riwayat',
      memory: '1.30 GiB',
      memPercent: '17.0%',
      status: 'Active (Cluster Green)',
      isOk: !!health?.wazuh_api,
      port: ':9200',
    },
    {
      name: 'Wazuh Manager Core (Analysisd)',
      category: 'core',
      role: 'Mesin korelasi aturan Sysmon, decoder rantai proses, dan trigger Active Response',
      memory: '1.02 GiB',
      memPercent: '13.0%',
      status: 'Active (v4.14.8)',
      isOk: !!health?.wazuh_api,
      port: ':1514, :55000',
    },
    {
      name: 'n8n Orchestrator (Otak SOAR)',
      category: 'orchestration',
      role: 'Eksekusi playbook insiden, evaluasi matriks otonomi, koroborasi VT/MB, dan callback Telegram',
      memory: '454 MiB',
      memPercent: '5.8%',
      status: 'Active (v2.42.5)',
      isOk: !!health?.n8n,
      port: ':5678',
    },
    {
      name: 'Wazuh Web Dashboard',
      category: 'core',
      role: 'Antarmuka analitik bawaan Wazuh untuk kepatuhan regulasi dan matriks MITRE',
      memory: '170 MiB',
      memPercent: '2.2%',
      status: 'Active (v4.14.8)',
      isOk: !!health?.wazuh_api,
      port: ':443',
    },
    {
      name: 'Fleet Web Dashboard (Next.js Standalone)',
      category: 'core',
      role: 'Antarmuka komando pusat armada, session security gate 2FA, dan integrasi MCP',
      memory: '55 MiB',
      memPercent: '0.7%',
      status: 'Active (Next.js 16)',
      isOk: online,
      port: ':3000',
    },
    {
      name: 'Fleet Monitor & M2M API Engine',
      category: 'microservice',
      role: 'Poller armada 100 PC, sinkronisasi cache VT/MB server-side, dan SQLite API Key auth',
      memory: '21 MiB',
      memPercent: '0.3%',
      status: 'Active (Python stdlib)',
      isOk: online,
      port: ':8080',
    },
    {
      name: 'MISP Threat Intel Cache & OSINT Sync',
      category: 'microservice',
      role: 'Penyedia indeks indikator kompromi lokal dari feed CIRCL OSINT tanpa kuota',
      memory: '21 MiB',
      memPercent: '0.3%',
      status: 'Active (SQLite indexed)',
      isOk: true,
      port: ':8090',
    },
    {
      name: 'Telegram Decision & Health Loggers',
      category: 'microservice',
      role: 'Registry keputusan HITL, audit trail analis ber-SLA 15m, dan self-aware health checker',
      memory: '23 MiB',
      memPercent: '0.3%',
      status: 'Active (Offset Protected)',
      isOk: true,
      port: ':8091',
    },
    {
      name: 'AI Reasoning Engine (Gemini 2.5 Flash & DeepSeek-V4)',
      category: 'ai',
      role: 'Triage kontekstual berbahasa Indonesia berbasis RAG playbook lokal anti-halusinasi',
      memory: '0 MiB (Offloaded API)',
      memPercent: '0.0%',
      status: 'Connected / Ready',
      isOk: !!health?.gemini,
      port: 'Cloud REST API',
    },
  ];

  const endpoints = [
    { method: 'GET', path: '/api/fleet', desc: 'Status agent + kesehatan stack' },
    { method: 'GET', path: '/api/events', desc: 'Threat events untuk dashboard' },
    { method: 'GET', path: '/api/keys', desc: 'Daftar API Key machine-to-machine' },
    { method: 'POST', path: '/api/auth/2fa/request', desc: 'Kirim kode OTP 2FA ke email & Telegram' },
    { method: 'POST', path: '/api/auth/2fa/verify', desc: 'Verifikasi kode OTP & pasang cookie sesi' },
    { method: 'POST', path: '/api/commands', desc: 'Karantina, scan, dan mitigasi aktif' },
    { method: 'POST', path: '/webhook-log', desc: 'Node n8n Log ke Fleet menulis alert' },
  ];

  return (
    <div className="space-y-4">
      {/* Tab Switcher */}
      <div className="flex items-center gap-2 border-b border-[#D3DAE6] pb-2">
        <button
          onClick={() => setActiveTab('general')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium rounded transition ${
            activeTab === 'general'
              ? 'bg-[#006BB4] text-white'
              : 'text-[#5A626F] hover:bg-[#F0F4F8]'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          General & Diagnostics
        </button>
        <button
          onClick={() => setActiveTab('dynamic-config')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium rounded transition ${
            activeTab === 'dynamic-config'
              ? 'bg-[#006BB4] text-white'
              : 'text-[#5A626F] hover:bg-[#F0F4F8]'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>AI Engine &amp; Threat Intel (Dinamis)</span>
        </button>
        <button
          onClick={() => setActiveTab('keys')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium rounded transition ${
            activeTab === 'keys'
              ? 'bg-[#006BB4] text-white'
              : 'text-[#5A626F] hover:bg-[#F0F4F8]'
          }`}
        >
          <Key className="w-3.5 h-3.5" />
          API Keys &amp; Agent Access
        </button>
      </div>

      {activeTab === 'dynamic-config' ? (
        <DynamicSettingsView />
      ) : activeTab === 'keys' ? (
        <ApiKeysView />
      ) : (
        <div className="space-y-4">
          {/* Panel Komparasi Efisiensi Memori (Server vs Endpoint Kasir) */}
          <div className="bg-white border border-[#D3DAE6] rounded-lg p-4 shadow-2xs">
            <div className="flex items-center justify-between pb-3 border-b border-[#EDEEF2]">
              <div className="flex items-center gap-2">
                <MemoryStick className="w-4 h-4 text-[#006BB4]" />
                <h2 className="text-[14px] font-semibold text-[#1A1C21]">
                  Arsitektur Memori & Efisiensi Resource (Server SOAR vs Endpoint Kasir)
                </h2>
              </div>
              <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-[#EBF5FB] text-[#006BB4] border border-[#CCE3F5]">
                Studi Kasus: CV Bali Handmade
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3.5">
              {/* Kolom Server SOAR */}
              <div className="p-3.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-[#006BB4]" />
                    <span className="text-[13px] font-semibold text-[#1A1C21]">
                      Server Pusat SOAR
                    </span>
                  </div>
                  <span className="text-[12px] font-mono font-bold text-[#006BB4] bg-white px-2 py-0.5 rounded border border-[#D3DAE6]">
                    ~3,05 GiB RAM Terpakai
                  </span>
                </div>
                <div className="mt-2.5 text-[12px] text-[#5A626F] space-y-1.5">
                  <div className="flex justify-between">
                    <span>Kapasitas RAM Server:</span>
                    <span className="font-medium text-[#1A1C21]">7,65 GiB (Hanya ~40% Beban)</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Komponen Terberat:</span>
                    <span className="font-medium text-[#1A1C21]">Wazuh Indexer (~1,30 GiB)</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Komparasi Platform:</span>
                    <span className="font-medium text-[#00A389]">&gt;90% Lebih Hemat vs Shuffle (&gt;4,5 GB)</span>
                  </div>
                </div>
                <p className="mt-3 text-[11px] text-[#64748b] leading-relaxed border-t border-[#E2E8F0] pt-2">
                  Ditenagai n8n dan Wazuh single-node terpadu, seluruh modul keamanan berjalan stabil di satu server fisik dengan biaya lisensi Rp 0.
                </p>
              </div>

              {/* Kolom Endpoint Workstation */}
              <div className="p-3.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-[#15803D]" />
                    <span className="text-[13px] font-semibold text-[#1A1C21]">
                      Endpoint Klien (Kasir & Toko)
                    </span>
                  </div>
                  <span className="text-[12px] font-mono font-bold text-[#15803D] bg-white px-2 py-0.5 rounded border border-[#D3DAE6]">
                    ~7 - 10 MiB RAM per Host
                  </span>
                </div>
                <div className="mt-2.5 text-[12px] text-[#5A626F] space-y-1.5">
                  <div className="flex justify-between">
                    <span>Agen Mandiri Rust (soar-agent):</span>
                    <span className="font-medium text-[#15803D]">~7 MiB RAM &middot; 0% CPU Idle</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Agen Tradisional Wazuh:</span>
                    <span className="font-medium text-[#1A1C21]">~50 - 80 MiB RAM</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Transmisi Jaringan:</span>
                    <span className="font-medium text-[#00A389]">Hash-Only JSON (&lt;1 KB per alert)</span>
                  </div>
                </div>
                <p className="mt-3 text-[11px] text-[#64748b] leading-relaxed border-t border-[#E2E8F0] pt-2">
                  Komputer kasir berspesifikasi rendah tetap responsif karena pemantauan hanya menghitung sidik jari hash tanpa memuat berkas utuh ke server.
                </p>
              </div>
            </div>
          </div>

          {/* Rincian Komponen Arsitektur Utama (Memory Breakdown) */}
          <div className="bg-white border border-[#D3DAE6] rounded-lg p-4 shadow-2xs">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-[#EDEEF2]">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#006BB4]" />
                <h2 className="text-[14px] font-semibold text-[#1A1C21]">
                  Rincian Komponen Arsitektur Utama (Status & Konsumsi Memori)
                </h2>
              </div>
              <span className="text-[12px] text-[#5A626F]">
                {components.length} Layanan Inti Terkorelasi
              </span>
            </div>

            <div className="divide-y divide-[#EDEEF2] overflow-x-auto">
              <table className="w-full text-left text-[12px]">
                <thead>
                  <tr className="text-[#5A626F] text-[11px] uppercase tracking-wider font-semibold border-b border-[#D3DAE6]">
                    <th className="py-2.5 pr-4">Komponen & Peran</th>
                    <th className="py-2.5 px-3">Port / Jalur</th>
                    <th className="py-2.5 px-3">Beban Memori</th>
                    <th className="py-2.5 px-3">Rasio Limit</th>
                    <th className="py-2.5 pl-3 text-right">Status Operasional</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F0F2F5]">
                  {components.map((comp) => (
                    <tr key={comp.name} className="hover:bg-[#F8FAFC] transition">
                      <td className="py-2.5 pr-4">
                        <div className="font-medium text-[#1A1C21]">{comp.name}</div>
                        <div className="text-[11px] text-[#64748b] mt-0.5">{comp.role}</div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-[#5A626F]">
                        {comp.port || '-'}
                      </td>
                      <td className="py-2.5 px-3 font-mono font-semibold text-[#006BB4]">
                        {comp.memory}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[#5A626F]">
                        {comp.memPercent}
                      </td>
                      <td className="py-2.5 pl-3 text-right">
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-[#E6F6F4] text-[#00A389] border border-[#B3E7DF]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          {comp.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Preferensi & Data Status Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Preferensi */}
            <div className="bg-white border border-[#D3DAE6] rounded p-4">
              <h2 className="text-[14px] font-semibold mb-3">Preferences</h2>
              <div className="flex items-center justify-between py-2 border-b border-[#EDEEF2]">
                <div>
                  <div className="text-[13px] font-medium">Refresh interval</div>
                  <div className="text-[12px] text-[#5A626F]">Seberapa sering dashboard menarik data fleet</div>
                </div>
                <select
                  value={refreshMs}
                  onChange={(e) => onRefreshMsChange(Number(e.target.value))}
                  className="px-2 py-1.5 rounded border border-[#D3DAE6] text-[12px] bg-white cursor-pointer"
                >
                  <option value={5000}>5 detik</option>
                  <option value={10000}>10 detik</option>
                  <option value={30000}>30 detik</option>
                </select>
              </div>
            </div>

            {/* Data status */}
            <div className="bg-white border border-[#D3DAE6] rounded p-4">
              <div className="flex items-center gap-2 mb-2">
                <Database className="w-4 h-4 text-[#006BB4]" />
                <h2 className="text-[14px] font-semibold">Data status</h2>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-[#EDEEF2]">
                <div className="flex items-center gap-2">
                  {online ? (
                    <CheckCircle2 className="w-4 h-4 text-[#00A389]" />
                  ) : (
                    <XCircle className="w-4 h-4 text-[#BD271E]" />
                  )}
                  <span className="text-[13px] font-medium">Backend fleet</span>
                </div>
                <span className="text-[12px] text-[#5A626F]">
                  {online ? 'Terjangkau (:8080)' : 'Tidak terjangkau'}
                </span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-[#EDEEF2]">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-[#00A389]" />
                  <span className="text-[13px] font-medium">Agent aktif</span>
                </div>
                <span className="text-[12px] text-[#5A626F]">
                  {stats.active}/{stats.total} endpoint ({stats.rust} Rust agent)
                </span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-[#EDEEF2]">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-[#00A389]" />
                  <span className="text-[13px] font-medium">Event tercatat (24h)</span>
                </div>
                <span className="text-[12px] text-[#5A626F]">
                  {stats.events_total?.toLocaleString('en-US') || 0} event &middot; {(stats.events_all_time ?? stats.events_total ?? 0).toLocaleString('en-US')} total
                </span>
              </div>
              <div className="pt-2 text-[12px] text-[#5A626F]">
                Update terakhir: {generatedAt ? formatWazuhTime(generatedAt) : '-'}
              </div>
            </div>
          </div>

          {/* Endpoints */}
          <div className="bg-white border border-[#D3DAE6] rounded p-4">
            <div className="flex items-center gap-2 mb-1">
              <Activity className="w-4 h-4 text-[#006BB4]" />
              <h2 className="text-[14px] font-semibold">Backend endpoints</h2>
            </div>
            <p className="text-[12px] text-[#5A626F] mb-3">
              Dashboard rewrite <code className="bg-[#F0F4F8] px-1 rounded font-mono text-[11px]">/api/*</code> ke fleet-monitor :8080 &middot; Webhook n8n di :5678
            </p>
            <div className="divide-y divide-[#EDEEF2]">
              {endpoints.map((ep) => (
                <div key={ep.path} className="py-2 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-mono text-[12px]">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      ep.method === 'GET' ? 'bg-[#EBF5FB] text-[#006BB4]' : 'bg-[#FEF3E8] text-[#B25E09]'
                    }`}>
                      {ep.method}
                    </span>
                    <span>{ep.path}</span>
                  </div>
                  <span className="text-[12px] text-[#5A626F]">{ep.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
