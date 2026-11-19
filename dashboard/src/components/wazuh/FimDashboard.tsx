'use client';

import React, { useMemo, useState } from 'react';
import { WuiIcon } from '../wui/WuiIcon';

import { formatWazuhTime, severityLevel, useEventHistory, periodToWindow } from '@/lib/fleet';
import { PeriodFilter } from './PeriodFilter';
import { WuiHealth, WuiModal } from '../wui/WuiPrimitives';
import type { PeriodValue, FleetEvent } from '@/lib/fleet';
import { postCommand } from '@/lib/commands';

const DEFAULT_PERIOD: PeriodValue = { preset: '7d', since: null, until: null };

function formatFileSize(bytes: number | string | undefined): string {
  if (bytes === undefined || bytes === null || bytes === '' || bytes === '-') return '-';
  const n = typeof bytes === 'number' ? bytes : parseInt(String(bytes), 10);
  if (isNaN(n) || n < 0) return String(bytes);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function resolveFileMetadata(e: FleetEvent | undefined) {
  const lastAnalysis = e?.ts ? formatWazuhTime(e.ts) : '-';
  const lastModified = e?.mtime
    ? formatWazuhTime(e.mtime)
    : e?.ts
    ? formatWazuhTime(e.ts)
    : '-';
  const user = e?.uname || 'N/A';
  const userId =
    e?.uid !== undefined && e?.uid !== '' && e?.uid !== null ? String(e.uid) : 'N/A';
  const group = e?.gname || 'N/A';
  const groupId =
    e?.gid !== undefined && e?.gid !== '' && e?.gid !== null ? String(e.gid) : 'N/A';
  const size = formatFileSize(e?.size);
  const inode = e?.inode ? String(e.inode) : '-';

  const md5 = e?.md5 || '-';
  const sha1 = e?.sha1 || '-';
  const sha256 = e?.hash || '-';
  const permissions = e?.perm || '-';

  return {
    lastAnalysis,
    lastModified,
    user,
    userId,
    group,
    groupId,
    size,
    inode,
    md5,
    sha1,
    sha256,
    permissions,
  };
}

export function FimDashboard() {
  const [activeSubtab, setActiveSubtab] = useState<'inventory' | 'dashboard' | 'events'>('inventory');
  const [selectedPath, setSelectedPath] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [period, setPeriod] = useState<PeriodValue>(DEFAULT_PERIOD);
  const [arState, setArState] = useState<Record<string, string>>({});
  const [copiedHash, setCopiedHash] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{
    agentId: string;
    action: 'quarantine' | 'restore';
    target: string;
  } | null>(null);

  const handleCopyHash = (hash: string) => {
    if (!hash || hash === '-') return;
    try {
      navigator.clipboard?.writeText(hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    } catch {}
  };

  const timeWindow = useMemo(() => periodToWindow(period), [period]);
  const { events } = useEventHistory(
    { since: timeWindow.since, until: timeWindow.until, source: 'all', limit: 500 },
    30000
  );

  /** Reset pilihan file + pencarian (tombol X di header detail). */
  const resetSelection = () => {
    setSelectedPath('');
    setSearchTerm('');
  };

  /** Buka dialog konfirmasi aksi karantina atau pemulihan ke agent. */
  function handleQueueAction(
    agentId: string,
    action: 'quarantine' | 'restore',
    target: string
  ) {
    setConfirmAction({ agentId, action, target });
  }

  /** Eksekusi perintah Active Response setelah dikonfirmasi in-app. */
  async function executeQueuedAction(
    agentId: string,
    action: 'quarantine' | 'restore',
    target: string
  ) {
    setConfirmAction(null);
    setArState((s) => ({ ...s, [target]: 'mengirim...' }));
    try {
      const r = await postCommand({ agent_id: agentId, action, target });
      const j = await r.json();
      setArState((s) => ({
        ...s,
        [target]: r.ok && j.status === 'queued' ? 'queued' : `gagal: ${j.error || r.status}`,
      }));
    } catch {
      setArState((s) => ({ ...s, [target]: 'gagal: jaringan' }));
    }
  }

  // Satu baris per kombinasi (agent_id, path) unik agar path sama di agent berbeda tidak saling menimpa.
  const files = useMemo(() => {
    const seen = new Map<string, FleetEvent>();
    events.forEach((e) => {
      if (!e.path) return;
      const key = `${e.agent_id || e.agent || '-'}:${e.path}`;
      if (!seen.has(key)) {
        seen.set(key, e);
      }
    });
    return [...seen.values()];
  }, [events]);

  const currentFile = files.find((f) => f.path === selectedPath) || files[0];
  const currentPath = currentFile?.path || '-';
  const fileEvents = currentFile ? events.filter((e) => e.path === currentFile.path) : [];
  const latestEvent = fileEvents[0] || currentFile;
  const latestLevel = latestEvent ? severityLevel(latestEvent.severity) : 0;
  const latestSeverity = (latestEvent?.severity || 'INFO').toUpperCase();
  const fileHash = latestEvent?.hash || currentFile?.hash || '';
  const agentId = latestEvent?.agent_id || latestEvent?.agent || '001';

  const metadata = resolveFileMetadata(latestEvent);

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
      {/* Sub-tabs + kontrol periode */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#D3DAE6] pb-2 text-[13px]">
        <div className="flex items-center gap-6">
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
        <PeriodFilter value={period} onChange={setPeriod} />
      </div>

      {activeSubtab === 'dashboard' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 bg-white border border-[#D3DAE6] rounded-[4px] divide-y sm:divide-y-0 sm:divide-x divide-[#E9EDF3] text-center">
            <div className="py-3 px-4">
              <div className="text-[12px] text-[#535966] font-medium">File termonitor</div>
              <div className="text-[24px] font-semibold text-[#1A1C21] tabular-nums leading-tight mt-1">{files.length}</div>
            </div>
            <div className="py-3 px-4">
              <div className="text-[12px] text-[#535966] font-medium">Total hits</div>
              <div className="text-[24px] font-semibold text-[#007871] tabular-nums leading-tight mt-1">{totalHits}</div>
            </div>
            <div className="py-3 px-4">
              <div className="text-[12px] text-[#535966] font-medium">File dengan hits terbanyak</div>
              <div className="text-[13px] font-mono text-[#1A1C21] mt-2 truncate" title={topFiles[0]?.[0] || '-'}>
                {topFiles[0]?.[0] || '-'}
              </div>
            </div>
          </div>
          <div className="bg-white border border-[#D3DAE6] rounded-[4px] p-4">
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
                    title={`${path} (${n} hits, klik untuk detail)`}
                  >
                    <div className="flex items-center justify-between text-[12px] mb-1">
                      <span className="font-mono text-[#006BB4] hover:underline truncate max-w-[70%]">{path}</span>
                      <span className="font-semibold text-[#5A626F] tabular-nums">{n}</span>
                    </div>
                    <div className="h-2 bg-[#F0F4F8] rounded">
                      <div className="h-2 bg-[#006BB4] rounded" style={{ width: `${Math.round((n / topMax) * 100)}%` }} />
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <div className="text-[13px] text-[#69707D]">Belum ada event. Drop EICAR di folder yang diawasi agent.</div>
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
                <tr className="border-b border-[#D3DAE6] text-[#5A626F] font-semibold bg-[#FAFBFD]">
                  <th className="py-2 px-3">Time ↓</th>
                  <th className="py-2 px-3">Path</th>
                  <th className="py-2 px-3">Action</th>
                  <th className="py-2 px-3">Agent</th>
                  <th className="py-2 px-3 text-center">Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EBEFF5]">
                {events.slice(0, 100).map((e, i) => {
                  const level = severityLevel(e.severity);
                  return (
                    <tr key={`${e.ts}-${i}`} className="hover:bg-[#FAFBFD]">
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

          <div className="text-[11px] font-semibold text-[#69707D]">File</div>

          <div className="space-y-0.5 overflow-y-auto max-h-[600px] text-[12px] font-mono">
            {filteredFiles.map((file) => (
              <button
                key={file.path}
                onClick={() => setSelectedPath(file.path)}
                className={`w-full text-left px-2 py-1.5 rounded truncate transition-colors ${
                  currentPath === file.path
                    ? 'bg-[#EBF5FB] text-[#006BB4] font-semibold'
                    : 'text-[#5A626F] hover:bg-[#FAFBFD]'
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
            Total: {filteredFiles.length} file
          </div>
        </div>

        {/* Right Detail Pane */}
        <div className="md:col-span-3 space-y-4">
          {/* File Header and Details */}
          <div className="bg-white border border-[#D3DAE6] rounded p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#EBEFF5] pb-3">
              <div className="text-[16px] font-semibold text-[#1A1C21] font-mono">{currentPath}</div>
              <button onClick={resetSelection} title="Reset pilihan file + pencarian" className="text-[#69707D] hover:text-[#1A1C21]" aria-label="Reset">
                <WuiIcon type="cross" size="m" />
              </button>
            </div>

            <div className="flex items-center gap-1.5 text-[13px] font-semibold text-[#1A1C21]">
              <WuiIcon type="arrowDown" size="m" />
              <span>Details</span>
            </div>

            {/* Metadata 3-Column Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-y-4 gap-x-6 text-[12px]">
              <div className="flex items-start gap-2.5">
                <WuiIcon type="clock" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">Last analysis</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.lastAnalysis}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="clock" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">Last modified</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.lastModified}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="user" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">User</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.user}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="user" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">User ID</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.userId}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="usersRolesApp" size="m" className="ouiIcon--mono text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">Group</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.group}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="usersRolesApp" size="m" className="ouiIcon--mono text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">Group ID</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.groupId}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="storage" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">Size</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.size}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="document" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">Inode</div>
                  <div className="font-medium text-[#1A1C21]">{metadata.inode}</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="lock" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">MD5</div>
                  <div className="font-mono text-[#1A1C21] text-[11px] truncate max-w-[180px]">
                    {metadata.md5}
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="lock" size="m" className="text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">SHA1</div>
                  <div className="font-mono text-[#1A1C21] text-[11px] truncate max-w-[180px]">
                    {metadata.sha1}
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2.5 md:col-span-2">
                <WuiIcon type="lock" size="m" className="text-[#006BB4] mt-0.5" />
                <div className="min-w-0">
                  <div className="text-[#69707D]">SHA256</div>
                  <div className="font-mono text-[#1A1C21] text-[11px] truncate" title={metadata.sha256}>
                    {metadata.sha256}
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2.5">
                <WuiIcon type="securityApp" size="m" className="ouiIcon--mono text-[#006BB4] mt-0.5" />
                <div>
                  <div className="text-[#69707D]">Permissions</div>
                  <div className="font-mono text-[#1A1C21]">{metadata.permissions}</div>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Intelligence & Security Assessment Card */}
          <div className="bg-white border border-[#D3DAE6] rounded-[4px] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#EBEFF5] pb-3">
              <div className="flex items-center gap-2">
                <WuiIcon type="arrowDown" size="m" className="text-[#535966]" />
                <span className="text-[13px] font-semibold text-[#1A1C21]">
                  Threat Intelligence &amp; Security Assessment
                </span>
                {latestEvent && (
                  <span
                    className={`text-[12px] font-semibold ${
                      latestLevel >= 7
                        ? 'text-[#BD271E]'
                        : latestLevel >= 4
                        ? 'text-[#935E00]'
                        : 'text-[#535966]'
                    }`}
                  >
                    · Level {latestLevel} ({latestSeverity})
                  </span>
                )}
              </div>

              {/* Action Toolbar for Active Response (sembunyikan untuk kategori INFO) */}
              {currentPath !== '-' && (latestSeverity !== 'INFO' || Boolean(latestEvent?.verdict)) && (
                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-[#8A94A6] hidden sm:inline">Active Response:</span>
                  <button
                    type="button"
                    disabled={Boolean(arState[currentPath]) || !agentId}
                    onClick={() => handleQueueAction(agentId, 'quarantine', currentPath)}
                    title={`Karantina ${currentPath} di agent ${agentId || '-'}`}
                    className={`text-[11px] font-medium px-2.5 py-1 rounded transition-colors disabled:opacity-50 cursor-pointer ${
                      latestLevel >= 7
                        ? 'text-white bg-[#BD271E] hover:bg-[#9E1F18] font-semibold'
                        : 'text-[#5A626F] border border-[#D3DAE6] bg-white hover:bg-[#F5F7FA] hover:text-[#1A1C21]'
                    }`}
                  >
                    Karantina Berkas
                  </button>
                  <button
                    type="button"
                    disabled={Boolean(arState[currentPath]) || !agentId}
                    onClick={() => handleQueueAction(agentId, 'restore', currentPath)}
                    title={`Pulihkan ${currentPath} dari karantina di agent ${agentId || '-'}`}
                    className="text-[11px] font-medium text-[#5A626F] border border-[#D3DAE6] bg-white hover:bg-[#F5F7FA] hover:text-[#1A1C21] px-2.5 py-1 rounded transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    Pulihkan
                  </button>
                  {arState[currentPath] && (
                    <span role="status" aria-live="polite" className="text-[11px] text-[#5A626F] font-mono">
                      {arState[currentPath]}
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* Assessment Panel (Flat 1px border, no thick left bar / chrome slop) */}
            <div className="p-3.5 rounded border border-[#E1E6EB] bg-[#FAFBFD] space-y-1.5">
              {latestEvent?.ai ? (
                <div className="space-y-1.5">
                  <div className="text-[12px] font-semibold text-[#1A1C21]">
                    Analisis korelasi ancaman (SOAR Threat Intel)
                  </div>
                  <p className="text-[12px] text-[#343741] leading-relaxed">
                    {latestEvent.ai}
                  </p>
                </div>
              ) : (
                <div className="flex items-start gap-2.5">
                  {latestLevel >= 7 ? (
                    <WuiIcon type="crossInCircleFilled" size="m" className="text-[#BD271E] mt-0.5" />
                  ) : latestLevel >= 4 ? (
                    <WuiIcon type="alert" size="m" className="text-[#935E00] mt-0.5" />
                  ) : (
                    <WuiIcon type="checkInCircleFilled" size="m" className="text-[#017D73] mt-0.5" />
                  )}
                  <div className="space-y-1">
                    <div className="text-[12px] font-semibold text-[#1A1C21] flex items-center gap-1.5">
                      <span>
                        {latestLevel >= 7
                          ? 'Indikasi Perubahan Kritis'
                          : latestLevel >= 4
                          ? 'Perubahan Integritas Terdeteksi'
                          : 'Integritas Berkas Terverifikasi'}
                      </span>
                      {latestEvent?.rule_id && (
                        <span className="text-[11px] font-mono font-normal text-[#69707D]">
                          (Rule {latestEvent.rule_id})
                        </span>
                      )}
                    </div>
                    <p className="text-[12px] text-[#535966] leading-relaxed">
                      {latestEvent?.rule_desc
                        ? latestEvent.rule_desc
                        : latestLevel >= 7
                        ? `Perubahan integritas berkas terindikasi berisiko tinggi (Level ${latestLevel}). Periksa riwayat hash terhadap basis data ancaman dan verifikasi keabsahan proses pembuat berkas.`
                        : latestLevel >= 4
                        ? `Perubahan atribut atau konten berkas terdeteksi oleh Wazuh Syscheck (Level ${latestLevel}). Pastikan integritas konfigurasi sesuai baseline operasional.`
                        : 'Integritas berkas tercatat pada baseline lokal Wazuh Syscheck daemon tanpa anomali atribut atau kecocokan indikator ancaman (IoC).'}
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Assessment Status & Detection Source Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px]">
              <div className="bg-[#FAFBFD] border border-[#EBEFF5] rounded-[4px] p-3 space-y-1">
                <div className="text-[11px] font-medium text-[#69707D]">Status Asesmen &amp; Reputasi</div>
                <div className="flex items-center gap-2 pt-0.5">
                  {latestEvent?.verdict ? (
                    <span className="font-semibold text-[#BD271E]">{latestEvent.verdict}</span>
                  ) : latestLevel >= 7 ? (
                    <WuiHealth tone="danger">High Risk Anomaly</WuiHealth>
                  ) : latestLevel >= 4 ? (
                    <WuiHealth tone="warning">Suspicious / Changed</WuiHealth>
                  ) : (
                    <WuiHealth tone="success">Clean / Normal Baseline</WuiHealth>
                  )}
                  {latestEvent?.status && latestEvent.status !== 'detected' && (
                    <span className="text-[#5A626F] text-[11px] font-mono">
                      Event: {latestEvent.status}
                    </span>
                  )}
                </div>
              </div>

              <div className="bg-[#FAFBFD] border border-[#EBEFF5] rounded p-3 space-y-1">
                <div className="text-[11px] font-medium text-[#8A94A6]">Sumber Deteksi &amp; ID Agen</div>
                <div className="flex items-center gap-2 pt-0.5 text-[#1A1C21]">
                  <span className="font-mono font-medium">Agent {agentId}</span>
                  <span className="text-[#8A94A6]">&middot;</span>
                  <span className="text-[#5A626F]">
                    {latestEvent?.source === 'wazuh' ? 'Wazuh Syscheck (Indexer)' : 'SOAR FIM Pipeline'}
                  </span>
                </div>
              </div>
            </div>

            {/* External Threat Intel OSINT Pivots (sembunyikan untuk kategori INFO) */}
            {(latestSeverity !== 'INFO' || Boolean(latestEvent?.verdict)) && (
              <div className="bg-[#FAFBFD] border border-[#D3DAE6] rounded p-3 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-[12px] font-semibold text-[#343741]">
                    External Threat Intel Pivot (OSINT)
                  </div>
                  {fileHash && fileHash !== '-' && (
                    <button
                      type="button"
                      onClick={() => handleCopyHash(fileHash)}
                      className="inline-flex items-center gap-1 text-[11px] text-[#006BB4] hover:underline cursor-pointer"
                      title="Salin hash ke clipboard"
                    >
                      {copiedHash ? (
                        <>
                          <WuiIcon type="check" size="xs" className="text-[#017D73]" />
                          <span className="text-[#017D73] font-medium">Tersalin!</span>
                        </>
                      ) : (
                        <>
                          <WuiIcon type="copy" size="xs" className="text-[#535966]" />
                          <span>Salin Hash</span>
                        </>
                      )}
                    </button>
                  )}
                </div>

                {fileHash && fileHash !== '-' ? (
                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    <a
                      href={`https://www.virustotal.com/gui/file/${fileHash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[4px] border border-[#D3DAE6] bg-white text-[#1A1C21] hover:border-[#006BB4] hover:text-[#006BB4] transition-colors"
                      title="Periksa reputasi berkas di VirusTotal"
                    >
                      <span className="font-medium">VirusTotal</span>
                      <WuiIcon type="popout" size="xs" className="text-[#69707D]" />
                    </a>

                    <a
                      href={`https://bazaar.abuse.ch/sample/${fileHash}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[4px] border border-[#D3DAE6] bg-white text-[#1A1C21] hover:border-[#006BB4] hover:text-[#006BB4] transition-colors"
                      title="Cek sampel malware di MalwareBazaar (abuse.ch)"
                    >
                      <span className="font-medium">MalwareBazaar</span>
                      <WuiIcon type="popout" size="xs" className="text-[#69707D]" />
                    </a>

                    <a
                      href={`https://otx.alienvault.com/indicator/file/${fileHash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[4px] border border-[#D3DAE6] bg-white text-[#1A1C21] hover:border-[#006BB4] hover:text-[#006BB4] transition-colors"
                      title="Penyelidikan ancaman di AlienVault Open Threat Exchange"
                    >
                      <span className="font-medium">AlienVault OTX</span>
                      <WuiIcon type="popout" size="xs" className="text-[#69707D]" />
                    </a>
                  </div>
                ) : (
                  <div className="text-[11px] text-[#69707D] italic">
                    Hash berkas belum dikalkulasi oleh agent untuk penelusuran OSINT eksternal.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Recent Events Table */}
          <div className="bg-white border border-[#D3DAE6] rounded-[4px] p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-[#EBEFF5] pb-2">
              <div className="flex items-center gap-2 text-[13px] font-semibold text-[#1A1C21]">
                <WuiIcon type="arrowDown" size="m" />
                <span>Recent events</span>
                <button
                  onClick={() => setActiveSubtab('events')}
                  title="Lihat semua event di subtab Events"
                  className="text-[#006BB4] hover:text-[#005593]"
                >
                  <WuiIcon type="popout" size="s" />
                </button>
              </div>
              <div className="text-[12px] text-[#5A626F]">{fileEvents.length} hits</div>
            </div>

            <div className="overflow-x-auto text-[12px]">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-[#D3DAE6] text-[#5A626F] font-semibold bg-[#FAFBFD]">
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

      {/* In-App Active Response Confirmation Modal */}
      {confirmAction && (
        <WuiModal
          title={
            <>
              <WuiIcon
                type="alert"
                size="m"
                className={confirmAction.action === 'quarantine' ? 'text-[#BD271E]' : 'text-[#006BB4]'}
              />
              <span>Konfirmasi Active Response FIM</span>
            </>
          }
          onClose={() => setConfirmAction(null)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setConfirmAction(null)}
                className="px-3 py-1.5 rounded-[4px] border border-[#D3DAE6] text-[12px] font-medium text-[#535966] hover:bg-[#FAFBFD] transition cursor-pointer"
              >
                Batal
              </button>
              <button
                type="button"
                onClick={() =>
                  executeQueuedAction(
                    confirmAction.agentId,
                    confirmAction.action,
                    confirmAction.target
                  )
                }
                className={`px-3 py-1.5 rounded-[4px] text-[12px] font-semibold text-white transition cursor-pointer ${
                  confirmAction.action === 'quarantine'
                    ? 'bg-[#BD271E] hover:bg-[#9E1F18]'
                    : 'bg-[#006BB4] hover:bg-[#00538C]'
                }`}
              >
                Eksekusi Perintah
              </button>
            </>
          }
        >
          <div className="space-y-3">
            <p className="text-[12px] text-[#535966] leading-relaxed">
              Apakah Anda yakin ingin mengeksekusi{' '}
              <strong className="text-[#1A1C21] uppercase font-mono">{confirmAction.action}</strong> pada file berikut?
            </p>
            <div className="p-2.5 rounded-[4px] bg-[#FAFBFD] border border-[#D3DAE6] text-[11px] font-mono space-y-1">
              <div><span className="text-[#69707D]">Agent ID:</span> {confirmAction.agentId}</div>
              <div><span className="text-[#69707D]">Action:</span> {confirmAction.action}</div>
              <div className="break-all"><span className="text-[#69707D]">Target:</span> {confirmAction.target}</div>
            </div>
          </div>
        </WuiModal>
      )}
    </div>
  );
}
