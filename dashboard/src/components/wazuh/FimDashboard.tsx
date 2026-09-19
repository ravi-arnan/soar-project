'use client';

import React, { useMemo, useState } from 'react';
import {
  FileText,
  Clock,
  User,
  Users,
  HardDrive,
  Key,
  Shield,
  FileCheck2,
  ChevronDown,
  X,
  Search,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';

import { formatWazuhTime, severityLevel } from '@/lib/fleet';
import type { FleetEvent } from '@/lib/fleet';

interface FimDashboardProps {
  /** Event live dari /api/events — path unik dipakai sebagai daftar file termonitor. */
  events?: FleetEvent[];
}

export function FimDashboard({ events = [] }: FimDashboardProps) {
  const [activeSubtab, setActiveSubtab] = useState<'inventory' | 'dashboard' | 'events'>('inventory');
  const [selectedPath, setSelectedPath] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  /** Reset pilihan file + pencarian (tombol X di header detail). */
  const resetSelection = () => {
    setSelectedPath('');
    setSearchTerm('');
  };

  // Satu baris per path unik, hash & waktu diambil dari event terakhir path itu.
  const files = useMemo(() => {
    const seen = new Map<string, { path: string; hash: string; ts: string }>();
    events.forEach((e) => {
      if (e.path && !seen.has(e.path)) {
        seen.set(e.path, { path: e.path, hash: e.hash, ts: e.ts });
      }
    });
    return [...seen.values()];
  }, [events]);

  const currentFile = files.find((f) => f.path === selectedPath) || files[0];
  const currentPath = currentFile?.path || '-';
  const fileEvents = currentFile ? events.filter((e) => e.path === currentFile.path) : [];

  const filteredFiles = files.filter((f) =>
    f.path.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Ringkasan untuk subtab Dashboard: hitung dari event live.
  const totalHits = events.length;
  const topFiles = useMemo(() => {
    const counts = new Map<string, number>();
    events.forEach((e) => {
      if (e.path) counts.set(e.path, (counts.get(e.path) || 0) + 1);
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [events]);
  const topMax = topFiles.length ? topFiles[0][1] : 1;

  const subtabCls = (active: boolean) =>
    `font-medium pb-2.5 -mb-2 transition-colors ${
      active
        ? 'border-b-2 border-[#006BB4] text-[#006BB4]'
        : 'text-[#5A626F] hover:text-[#1A1C21]'
    }`;

  return (
    <div className="space-y-4">
      {/* Sub-tabs */}
      <div className="flex items-center gap-6 border-b border-[#D3DAE6] pb-2 text-[13px]">
        <button onClick={() => setActiveSubtab('inventory')} className={subtabCls(activeSubtab === 'inventory')}>
          Inventory
        </button>
        <button onClick={() => setActiveSubtab('dashboard')} className={subtabCls(activeSubtab === 'dashboard')}>
          Dashboard
        </button>
        <button onClick={() => setActiveSubtab('events')} className={subtabCls(activeSubtab === 'events')}>
          Events
        </button>
      </div>

      {activeSubtab === 'dashboard' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
            <div>
              <div className="text-[12px] text-[#5A626F] font-medium">File termonitor</div>
              <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">{files.length}</div>
            </div>
            <div>
              <div className="text-[12px] text-[#5A626F] font-medium">Total hits</div>
              <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">{totalHits}</div>
            </div>
            <div>
              <div className="text-[12px] text-[#5A626F] font-medium">File dengan hits terbanyak</div>
              <div className="text-[13px] font-mono text-[#1A1C21] mt-2 truncate" title={topFiles[0]?.[0] || '-'}>
                {topFiles[0]?.[0] || '-'}
              </div>
            </div>
          </div>
          <div className="bg-white border border-[#D3DAE6] rounded p-4">
            <h2 className="text-[14px] font-semibold mb-3">Top 5 file per hits</h2>
            {topFiles.length ? (
              <div className="space-y-2">
                {topFiles.map(([path, n]) => (
                  <button
                    key={path}
                    onClick={() => {
                      setSelectedPath(path);
                      setActiveSubtab('inventory');
                    }}
                    className="w-full text-left"
                    title={`${path} — ${n} hits (klik untuk detail)`}
                  >
                    <div className="flex items-center justify-between text-[12px] mb-1">
                      <span className="font-mono text-[#006BB4] hover:underline truncate max-w-[70%]">{path}</span>
                      <span className="font-semibold text-[#5A626F]">{n}</span>
                    </div>
                    <div className="h-2 bg-[#F0F4F8] rounded">
                      <div className="h-2 bg-[#006BB4] rounded" style={{ width: `${Math.round((n / topMax) * 100)}%` }} />
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <div className="text-[13px] text-[#8A94A6]">belum ada event — drop EICAR di folder yang diawasi agent</div>
            )}
          </div>
        </div>
      )}

      {activeSubtab === 'events' && (
        <div className="bg-white border border-[#D3DAE6] rounded p-4 space-y-3">
          <div className="text-[14px] font-semibold">Semua event integrity ({events.length})</div>
          <div className="overflow-x-auto text-[12px]">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[#D3DAE6] text-[#5A626F] font-semibold bg-[#F8FAFC]">
                  <th className="py-2 px-3">Time ↓</th>
                  <th className="py-2 px-3">Path</th>
                  <th className="py-2 px-3">Action</th>
                  <th className="py-2 px-3">Agent</th>
                  <th className="py-2 px-3 text-center">Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EBEFF5]">
                {[...events].reverse().map((e, i) => {
                  const level = severityLevel(e.severity);
                  return (
                    <tr key={`${e.ts}-${i}`} className="hover:bg-[#F8FAFC]">
                      <td className="py-2 px-3 text-[#5A626F] whitespace-nowrap">{formatWazuhTime(e.ts)}</td>
                      <td className="py-2 px-3 font-mono text-[#006BB4] truncate max-w-[280px]" title={e.path}>{e.path || '-'}</td>
                      <td className="py-2 px-3 font-medium text-[#1A1C21]">{e.status || '-'}</td>
                      <td className="py-2 px-3 text-[#1A1C21]">{e.agent || '-'}</td>
                      <td className={`py-2 px-3 text-center font-semibold ${level >= 7 ? 'text-[#BD271E]' : 'text-[#006BB4]'}`}>
                        {level}
                      </td>
                    </tr>
                  );
                })}
                {!events.length && (
                  <tr>
                    <td colSpan={5} className="py-4 text-center text-[#8A94A6]">
                      belum ada event untuk file ini
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeSubtab === 'inventory' && (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-start">
        {/* Left Files List Sidebar */}
        <div className="bg-white border border-[#D3DAE6] rounded p-3 space-y-3">
          <div className="flex items-center justify-between text-[13px] font-semibold text-[#1A1C21]">
            <span>Files ({files.length})</span>
          </div>

          <div className="relative">
            <input
              type="text"
              placeholder="Filter or search file"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-2 pr-2 py-1 border border-[#D3DAE6] rounded text-[12px] outline-none"
            />
          </div>

          <div className="text-[10px] uppercase font-bold text-[#8A94A6]">File ↑</div>

          <div className="space-y-0.5 overflow-y-auto max-h-[600px] text-[12px] font-mono">
            {filteredFiles.map((file) => (
              <button
                key={file.path}
                onClick={() => setSelectedPath(file.path)}
                className={`w-full text-left px-2 py-1.5 rounded truncate transition-colors ${
                  currentPath === file.path
                    ? 'bg-[#EBF5FB] text-[#006BB4] font-semibold'
                    : 'text-[#5A626F] hover:bg-[#F8FAFC]'
                }`}
                title={file.path}
              >
                {file.path}
              </button>
            ))}
            {!filteredFiles.length && (
              <div className="px-2 py-3 text-[#8A94A6]">belum ada file tercatat</div>
            )}
          </div>

          <div className="pt-2 border-t border-[#EBEFF5] text-[11px] text-[#8A94A6]">
            Rows per page: 15
          </div>
        </div>

        {/* Right Detail Pane */}
        <div className="md:col-span-3 space-y-4">
          {/* File Header and Details */}
          <div className="bg-white border border-[#D3DAE6] rounded p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#EBEFF5] pb-3">
              <div className="text-[16px] font-semibold text-[#1A1C21] font-mono">{currentPath}</div>
              <button onClick={resetSelection} title="Reset pilihan file + pencarian" className="text-[#8A94A6] hover:text-[#1A1C21]">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center gap-1.5 text-[13px] font-semibold text-[#1A1C21]">
              <ChevronDown className="w-4 h-4" />
              <span>Details</span>
            </div>

            {/* Metadata 3-Column Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-y-4 gap-x-6 text-[12px]">
              <div className="flex items-start gap-2.5">
                <Clock className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">Last analysis</div>
                  <div className="font-medium text-[#1A1C21]">
                    {currentFile?.ts ? formatWazuhTime(currentFile.ts) : '-'}
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <Clock className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">Last modified</div>
                  <div className="font-medium text-[#1A1C21]">-</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <User className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">User</div>
                  <div className="font-medium text-[#1A1C21]">-</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <User className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">User ID</div>
                  <div className="font-medium text-[#1A1C21]">-</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <Users className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">Group</div>
                  <div className="font-medium text-[#1A1C21]">-</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <Users className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">Group ID</div>
                  <div className="font-medium text-[#1A1C21]">-</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <HardDrive className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">Size</div>
                  <div className="font-medium text-[#1A1C21]">-</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <FileText className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">Inode</div>
                  <div className="font-medium text-[#1A1C21]">-</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <Key className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">MD5</div>
                  <div className="font-mono text-[#1A1C21] text-[11px] truncate max-w-[180px]">-
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <Key className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">SHA1</div>
                  <div className="font-mono text-[#1A1C21] text-[11px] truncate max-w-[180px]">-
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2.5 md:col-span-2">
                <Key className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div className="min-w-0">
                  <div className="text-[#8A94A6]">SHA256</div>
                  <div className="font-mono text-[#1A1C21] text-[11px] truncate" title={currentFile?.hash || ''}>
                    {currentFile?.hash || '-'}
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <Shield className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
                <div>
                  <div className="text-[#8A94A6]">Permissions</div>
                  <div className="font-mono text-[#1A1C21]">-</div>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Events Table */}
          <div className="bg-white border border-[#D3DAE6] rounded p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-[#EBEFF5] pb-2">
              <div className="flex items-center gap-2 text-[13px] font-semibold text-[#1A1C21]">
                <ChevronDown className="w-4 h-4" />
                <span>Recent events</span>
                <button
                  onClick={() => setActiveSubtab('events')}
                  title="Lihat semua event di subtab Events"
                  className="text-[#006BB4] hover:text-[#005593]"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="text-[12px] text-[#5A626F]">{fileEvents.length} hits</div>
            </div>

            <div className="overflow-x-auto text-[12px]">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-[#D3DAE6] text-[#5A626F] font-semibold bg-[#F8FAFC]">
                    <th className="py-2 px-3">Time ↓</th>
                    <th className="py-2 px-3">Action</th>
                    <th className="py-2 px-3">Description</th>
                    <th className="py-2 px-3 text-center">Level</th>
                    <th className="py-2 px-3 text-right">Rule ID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#EBEFF5]">
                  {fileEvents.map((e, i) => {
                    const level = severityLevel(e.severity);
                    return (
                      <tr key={`${e.ts}-${i}`}>
                        <td className="py-2 px-3 text-[#5A626F]">{formatWazuhTime(e.ts)}</td>
                        <td className="py-2 px-3 font-medium text-[#1A1C21]">{e.status || '-'}</td>
                        <td className="py-2 px-3 text-[#1A1C21]">{e.ai || 'Integrity event'}</td>
                        <td
                          className={`py-2 px-3 text-center font-semibold ${
                            level >= 7 ? 'text-[#BD271E]' : 'text-[#006BB4]'
                          }`}
                        >
                          {level}
                        </td>
                        <td className="py-2 px-3 text-right font-medium text-[#006BB4]">
                          {(e.severity || 'INFO').toUpperCase()}
                        </td>
                      </tr>
                    );
                  })}
                  {!fileEvents.length && (
                    <tr>
                      <td colSpan={5} className="py-4 text-center text-[#8A94A6]">
                        belum ada event untuk file ini
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
      )}
    </div>
  );
}
