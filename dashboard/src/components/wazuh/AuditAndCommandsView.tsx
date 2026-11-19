'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import { WuiHealth, WuiPanel } from '../wui/WuiPrimitives';
import { formatWazuhTime } from '@/lib/fleet';

export interface CommandRecord {
  id: string;
  agent_id: string;
  action: string;
  target: string;
  status: 'queued' | 'delivered' | 'succeeded' | 'failed' | 'expired' | string;
  requested_by: string;
  created_at: string;
  delivered_at?: string;
  completed_at?: string;
  output?: string;
}

export interface AuditRecord {
  id: number;
  ts: string;
  actor: string;
  role: string;
  action: string;
  target: string;
  status: string;
  ip: string;
  detail: string;
  prev_hash: string;
  entry_hash: string;
}

export interface HitlDecisionRecord {
  did: string;
  hash: string;
  agent_id: string;
  agent_name?: string;
  filepath: string;
  filename?: string;
  severity?: string;
  tier?: string;
  title?: string;
  status: 'pending' | 'escalated' | 'resolved' | 'expired' | string;
  created_at?: string;
  age_secs?: number;
  overdue_secs?: number;
  action?: string;
  by?: string;
}

function statusBadgeStyle(status: string): string {
  switch (status) {
    case 'succeeded':
    case 'ok':
      return 'bg-[#E6F4F3] text-[#017D73] border-[#B2DFDB]';
    case 'delivered':
    case 'investigating':
      return 'bg-[#EBF5FB] text-[#006BB4] border-[#B8D5E5]';
    case 'queued':
    case 'pending':
      return 'bg-[#FEF6E8] text-[#B25E09] border-[#F5D9A8]';
    case 'failed':
    case 'denied':
    case 'error':
    case 'escalated':
      return 'bg-[#FDF3F2] text-[#BD271E] border-[#F5C2C0]';
    default:
      return 'bg-[#F0F4F8] text-[#535966] border-[#D3DAE6]';
  }
}

export function CommandQueueHistoryPanel({
  agentIdFilter,
  compact = false,
}: {
  agentIdFilter?: string;
  compact?: boolean;
}) {
  const [commands, setCommands] = useState<CommandRecord[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [loading, setLoading] = useState<boolean>(true);

  const load = useCallback(() => {
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
    const params = new URLSearchParams();
    if (agentIdFilter) params.set('agent_id', agentIdFilter);
    if (statusFilter && statusFilter !== 'all') params.set('status', statusFilter);
    params.set('limit', compact ? '25' : '100');

    fetch(`/api/commands/history?${params.toString()}`, { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) {
          setCommands(Array.isArray(d.commands) ? d.commands : []);
          setCounts(d.counts || {});
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [agentIdFilter, statusFilter, compact]);

  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  return (
    <div className="space-y-3 text-[12px]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {(['all', 'queued', 'delivered', 'succeeded', 'failed', 'expired'] as const).map((st) => {
            const count = st === 'all'
              ? Object.values(counts).reduce((a, b) => a + b, 0)
              : counts[st] || 0;
            const active = statusFilter === st;
            return (
              <button
                key={st}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded-[4px] border text-[11px] font-medium transition cursor-pointer ${
                  active
                    ? 'bg-[#006BB4] text-white border-[#006BB4]'
                    : 'bg-white text-[#535966] border-[#D3DAE6] hover:bg-[#FAFBFD]'
                }`}
              >
                <span className="uppercase">{st}</span>
                {!agentIdFilter && <span className="ml-1.5 font-mono opacity-80">({count})</span>}
              </button>
            );
          })}
        </div>
        <button
          type="button"
          onClick={load}
          className="px-2.5 py-1 rounded-[4px] border border-[#D3DAE6] text-[11px] text-[#535966] hover:bg-[#FAFBFD] cursor-pointer"
        >
          Muat ulang
        </button>
      </div>

      <div className="overflow-x-auto border border-[#D3DAE6] rounded-[4px] bg-white">
        <table className="w-full text-left text-[11.5px]">
          <thead>
            <tr className="border-b border-[#D3DAE6] bg-[#FAFBFD] text-[#535966] font-semibold">
              <th className="py-2 px-3">Waktu</th>
              <th className="py-2 px-3">Command ID</th>
              {!agentIdFilter && <th className="py-2 px-3">Agent</th>}
              <th className="py-2 px-3">Aksi</th>
              <th className="py-2 px-3">Target</th>
              <th className="py-2 px-3">Status ACK</th>
              <th className="py-2 px-3">Oleh</th>
              <th className="py-2 px-3">Output / Detail Eksekusi</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#EBEFF5]">
            {loading && commands.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-6 text-center text-[#8A94A6]">
                  Memuat riwayat command queue...
                </td>
              </tr>
            ) : commands.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-6 text-center text-[#8A94A6]">
                  Belum ada riwayat perintah Active Response untuk filter ini.
                </td>
              </tr>
            ) : (
              commands.map((c) => (
                <tr key={c.id} className="hover:bg-[#FAFBFD]">
                  <td className="py-2 px-3 whitespace-nowrap text-[#5A626F] font-mono">
                    {formatWazuhTime(c.created_at)}
                  </td>
                  <td className="py-2 px-3 font-mono text-[#1A1C21]">{c.id}</td>
                  {!agentIdFilter && (
                    <td className="py-2 px-3 font-mono font-semibold text-[#006BB4]">{c.agent_id}</td>
                  )}
                  <td className="py-2 px-3 font-mono uppercase font-semibold text-[#1A1C21]">
                    {c.action}
                  </td>
                  <td className="py-2 px-3 font-mono text-[#1A1C21] max-w-[240px] truncate" title={c.target}>
                    {c.target}
                  </td>
                  <td className="py-2 px-3">
                    <span
                      className={`inline-block px-2 py-0.5 rounded border text-[10.5px] font-semibold uppercase ${statusBadgeStyle(
                        c.status
                      )}`}
                    >
                      {c.status}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-[#5A626F]">{c.requested_by || '-'}</td>
                  <td className="py-2 px-3 font-mono text-[11px] text-[#535966] max-w-[280px] truncate" title={c.output || ''}>
                    {c.output || (c.status === 'queued' ? 'Menunggu agent poll' : c.status === 'delivered' ? 'Sedang dieksekusi agent' : '-')}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function AuditTrailPanel() {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [chainValid, setChainValid] = useState<boolean>(true);
  const [verifiedCount, setVerifiedCount] = useState<number>(0);
  const [brokenAtId, setBrokenAtId] = useState<number | null>(null);
  const [query, setQuery] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [actionsList, setActionsList] = useState<{ action: string; count: number }[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const load = useCallback(() => {
    const params = new URLSearchParams();
    params.set('verify', '1');
    params.set('limit', '150');
    if (actionFilter && actionFilter !== 'all') params.set('action', actionFilter);
    if (query.trim()) params.set('q', query.trim());

    fetch(`/api/audit?${params.toString()}`, { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) {
          setLogs(Array.isArray(d.logs) ? d.logs : []);
          setChainValid(Boolean(d.chain_valid));
          setVerifiedCount(Number(d.verified_count || 0));
          setBrokenAtId(d.broken_at_id ?? null);
          if (Array.isArray(d.actions)) setActionsList(d.actions);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [actionFilter, query]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[#D3DAE6] rounded-[4px] p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <WuiIcon
            type={chainValid ? 'checkInCircleFilled' : 'crossInCircleFilled'}
            size="m"
            className={chainValid ? 'text-[#017D73]' : 'text-[#BD271E]'}
          />
          <div>
            <div className="text-[13px] font-semibold text-[#1A1C21]">
              {chainValid
                ? 'Integritas Audit Trail Terverifikasi (SHA-256 Hash Chain OK)'
                : `Peringatan Integritas: Rantai Hash Rusak pada Entri #${brokenAtId}`}
            </div>
            <div className="text-[11.5px] text-[#535966]">
              {verifiedCount} entri berantai diverifikasi dari anchor GENESIS. Setiap perubahan database tanpa otorisasi memutus rantai hash.
            </div>
          </div>
        </div>
        <WuiHealth tone={chainValid ? 'success' : 'danger'}>
          {chainValid ? `Verified (${verifiedCount} blocks)` : 'Tamper Detected'}
        </WuiHealth>
      </div>

      <WuiPanel
        title="Centralized SOC Audit Trail"
        accentColor="#006BB4"
        right={
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="h-7 px-2 rounded border border-[#D3DAE6] text-[11.5px] bg-white"
            >
              <option value="all">Semua Aksi</option>
              {actionsList.map((a) => (
                <option key={a.action} value={a.action}>
                  {a.action} ({a.count})
                </option>
              ))}
            </select>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Cari actor, target, IP..."
              className="h-7 px-2.5 rounded border border-[#D3DAE6] text-[11.5px] bg-white w-48"
            />
            <button
              type="button"
              onClick={load}
              className="h-7 px-2.5 rounded border border-[#D3DAE6] text-[11.5px] text-[#535966] hover:bg-[#FAFBFD] cursor-pointer"
            >
              Verifikasi Ulang
            </button>
          </div>
        }
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[11.5px]">
            <thead>
              <tr className="border-b border-[#D3DAE6] bg-[#FAFBFD] text-[#535966] font-semibold">
                <th className="py-2 px-3">#</th>
                <th className="py-2 px-3">Waktu</th>
                <th className="py-2 px-3">Actor</th>
                <th className="py-2 px-3">Aksi</th>
                <th className="py-2 px-3">Target</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Detail</th>
                <th className="py-2 px-3">SHA-256 Chain</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E9EDF3]">
              {loading && logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-[#8A94A6]">
                    Memuat audit trail...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-[#8A94A6]">
                    Belum ada entri audit log yang cocok.
                  </td>
                </tr>
              ) : (
                logs.map((row) => (
                  <tr key={row.id} className="hover:bg-[#FAFBFD]">
                    <td className="py-2 px-3 font-mono text-[#8A94A6]">{row.id}</td>
                    <td className="py-2 px-3 whitespace-nowrap font-mono text-[#5A626F]">
                      {formatWazuhTime(row.ts)}
                    </td>
                    <td className="py-2 px-3">
                      <span className="font-medium text-[#1A1C21]">{row.actor}</span>
                      {row.role && (
                        <span className="ml-1.5 px-1.5 py-0.5 rounded bg-[#F0F4F8] text-[#535966] text-[10px] uppercase">
                          {row.role}
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 font-mono font-semibold text-[#006BB4]">{row.action}</td>
                    <td className="py-2 px-3 font-mono text-[#1A1C21] max-w-[180px] truncate" title={row.target}>
                      {row.target || '-'}
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${statusBadgeStyle(
                          row.status
                        )}`}
                      >
                        {row.status}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-[#535966] max-w-[260px] truncate" title={row.detail}>
                      {row.detail || '-'}
                    </td>
                    <td
                      className="py-2 px-3 font-mono text-[10.5px] text-[#8A94A6]"
                      title={`prev: ${row.prev_hash}\ncurr: ${row.entry_hash}`}
                    >
                      {row.entry_hash.slice(0, 12)}...
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </WuiPanel>
    </div>
  );
}

export function AgentCredentialLifecyclePanel({
  agentId,
  agentName,
  canManage,
}: {
  agentId: string;
  agentName: string;
  canManage: boolean;
}) {
  const [rotatedToken, setRotatedToken] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string>('');
  const [busy, setBusy] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  if (!canManage) return null;

  async function handleRotate() {
    if (
      typeof window !== 'undefined' &&
      !window.confirm(
        `Rotasi poll_token untuk agent ${agentId} (${agentName})? Token lama akan langsung tidak berlaku.`
      )
    ) {
      return;
    }
    setBusy(true);
    setStatusMsg('Membuat poll_token baru...');
    setRotatedToken(null);
    try {
      const res = await fetch('/api/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'rotate', agent_id: agentId }),
      });
      const data = await res.json();
      if (res.ok && data.success && data.result?.poll_token) {
        setRotatedToken(data.result.poll_token);
        setStatusMsg('Token berhasil dirotasi. Simpan token di bawah ini ke endpoint.');
      } else {
        setStatusMsg(`Gagal rotasi: ${data.error || res.status}`);
      }
    } catch {
      setStatusMsg('Gagal menghubungi server.');
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke() {
    const reason =
      typeof window !== 'undefined'
        ? window.prompt(
            `Cabut akses (revoke) poll_token untuk agent ${agentId} (${agentName})? Masukkan alasan singkat:`,
            'Token compromised / decommissioned'
          )
        : null;
    if (reason === null) return;
    setBusy(true);
    setStatusMsg('Mencabut token agent...');
    setRotatedToken(null);
    try {
      const res = await fetch('/api/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'revoke', agent_id: agentId, reason }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setStatusMsg(`Akses agent ${agentId} telah dicabut (revoked) dan antrean command dibatalkan.`);
      } else {
        setStatusMsg(`Gagal mencabut token: ${data.error || res.status}`);
      }
    } catch {
      setStatusMsg('Gagal menghubungi server.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3 text-[12px]">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-[#535966]">
          Kelola kredensial autentikasi <span className="font-mono">poll_token</span> untuk agent Rust{' '}
          <strong className="text-[#1A1C21]">{agentName} ({agentId})</strong>.
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={handleRotate}
            className="px-3 py-1.5 rounded-[4px] border border-[#006BB4] text-[#006BB4] hover:bg-[#EBF5FB] text-[11.5px] font-medium transition cursor-pointer disabled:opacity-50"
          >
            Rotate Poll Token
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={handleRevoke}
            className="px-3 py-1.5 rounded-[4px] border border-[#BD271E] text-[#BD271E] hover:bg-[#FDF3F2] text-[11.5px] font-medium transition cursor-pointer disabled:opacity-50"
          >
            Revoke Agent Access
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="text-[11.5px] text-[#1A1C21] bg-[#FAFBFD] border border-[#D3DAE6] rounded px-3 py-2">
          {statusMsg}
        </div>
      )}

      {rotatedToken && (
        <div className="p-3 rounded-[4px] bg-[#FEF6E8] border border-[#F5D9A8] space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11.5px] font-semibold text-[#935E00]">
              Token Baru (Hanya Ditampilkan Sekali):
            </span>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard?.writeText(rotatedToken);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="px-2 py-0.5 rounded bg-white border border-[#D3DAE6] text-[11px] font-medium text-[#1A1C21] cursor-pointer"
            >
              {copied ? 'Tersalin' : 'Salin Token'}
            </button>
          </div>
          <div className="font-mono text-[11.5px] bg-white border border-[#D3DAE6] rounded px-2.5 py-1.5 break-all select-all">
            {rotatedToken}
          </div>
          <div className="text-[11px] text-[#535966] font-mono">
            Perbarui di endpoint: <code>printf &apos;%s\n&apos; &apos;{rotatedToken}&apos; | sudo tee /etc/soar-agent/fleet.token &gt;/dev/null &amp;&amp; sudo systemctl restart soar-agent</code>
          </div>
        </div>
      )}
    </div>
  );
}

export function HitlPendingQueuePanel({
  canWrite,
  onResolved,
}: {
  canWrite: boolean;
  onResolved?: () => void;
}) {
  const [decisions, setDecisions] = useState<HitlDecisionRecord[]>([]);
  const [pendingCount, setPendingCount] = useState<number>(0);
  const [showHistory, setShowHistory] = useState<boolean>(false);
  const [busyDid, setBusyDid] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string>('');

  const load = useCallback(() => {
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
    fetch(`/api/hitl?all=${showHistory ? '1' : '0'}&limit=30`, { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d && Array.isArray(d.decisions)) {
          setDecisions(d.decisions);
          setPendingCount(Number(d.pending_count || 0));
        }
      })
      .catch(() => {});
  }, [showHistory]);

  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  async function resolveDecision(
    rec: HitlDecisionRecord,
    action: 'quarantine' | 'false_positive' | 'acknowledged'
  ) {
    setBusyDid(rec.did || rec.hash);
    setFeedback('');
    try {
      const res = await fetch('/api/hitl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did: rec.did,
          hash: rec.hash,
          agent_id: rec.agent_id,
          action,
          note: `Resolved via SOC Web Dashboard (${action})`,
        }),
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        const arMsg = data.ar_dispatched?.command_id
          ? ` (Command AR ${data.ar_dispatched.command_id} diantrekan ke agent ${rec.agent_id})`
          : '';
        setFeedback(`Keputusan HITL '${action}' untuk ${rec.filename || rec.filepath} tercatat${arMsg}.`);
        load();
        onResolved?.();
      } else {
        setFeedback(`Gagal memproses HITL: ${data.resolved?.error || data.error || res.status}`);
      }
    } catch {
      setFeedback('Gagal menghubungi endpoint HITL.');
    } finally {
      setBusyDid(null);
    }
  }

  if (pendingCount === 0 && !showHistory && !feedback) {
    return (
      <div className="bg-white border border-[#D3DAE6] rounded-[4px] px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-[12px]">
        <div className="flex items-center gap-2 text-[#535966]">
          <WuiIcon type="checkInCircleFilled" size="s" className="text-[#017D73]" />
          <span>
            <strong className="text-[#1A1C21]">Antrean Persetujuan HITL Bersih:</strong> Tidak ada insiden HIGH yang menunggu keputusan analis saat ini.
          </span>
        </div>
        <button
          type="button"
          onClick={() => setShowHistory(true)}
          className="text-[11.5px] text-[#006BB4] hover:underline font-medium cursor-pointer"
        >
          Lihat Riwayat Keputusan HITL
        </button>
      </div>
    );
  }

  return (
    <div className="bg-white border border-[#D3DAE6] rounded-[4px] overflow-hidden">
      <div
        className={`px-4 py-2.5 border-b border-[#D3DAE6] flex flex-wrap items-center justify-between gap-2 ${
          pendingCount > 0 ? 'bg-[#FEF6E8]' : 'bg-[#FAFBFD]'
        }`}
      >
        <div className="flex items-center gap-2 text-[12.5px] font-semibold text-[#1A1C21]">
          <WuiIcon
            type="alert"
            size="s"
            className={pendingCount > 0 ? 'text-[#B25E09]' : 'text-[#006BB4]'}
          />
          <span>
            Human-in-the-Loop (HITL) Decision Queue ({pendingCount} menunggu persetujuan)
          </span>
        </div>
        <div className="flex items-center gap-3 text-[11.5px]">
          <button
            type="button"
            onClick={() => setShowHistory((s) => !s)}
            className="text-[#006BB4] hover:underline font-medium cursor-pointer"
          >
            {showHistory ? 'Hanya Tampilkan Pending' : 'Tampilkan Semua Riwayat'}
          </button>
          <button
            type="button"
            onClick={load}
            className="text-[#535966] hover:text-[#1A1C21] cursor-pointer"
          >
            Refresh
          </button>
        </div>
      </div>

      {feedback && (
        <div className="px-4 py-2 bg-[#E6F4F3] border-b border-[#B2DFDB] text-[11.5px] text-[#017D73] font-medium">
          {feedback}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[11.5px]">
          <thead>
            <tr className="border-b border-[#E9EDF3] bg-[#FAFBFD] text-[#535966] font-semibold">
              <th className="py-2 px-3">ID / Waktu</th>
              <th className="py-2 px-3">Agent</th>
              <th className="py-2 px-3">Path Berkas / Target</th>
              <th className="py-2 px-3">Severity</th>
              <th className="py-2 px-3">Status SLA</th>
              <th className="py-2 px-3 text-right">Keputusan Analis (Dashboard HITL)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E9EDF3]">
            {decisions.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-4 text-center text-[#8A94A6]">
                  Tidak ada data keputusan HITL.
                </td>
              </tr>
            ) : (
              decisions.map((d) => {
                const isPending = d.status === 'pending' || d.status === 'escalated';
                const isBusy = busyDid === (d.did || d.hash);
                return (
                  <tr key={`${d.agent_id}-${d.hash}`} className="hover:bg-[#FAFBFD]">
                    <td className="py-2 px-3 font-mono text-[#5A626F]">
                      <div className="font-semibold text-[#1A1C21]">{d.did || d.hash.slice(0, 12)}</div>
                      <div className="text-[10.5px]">{d.created_at ? formatWazuhTime(d.created_at) : '-'}</div>
                    </td>
                    <td className="py-2 px-3">
                      <span className="font-mono font-semibold text-[#006BB4]">{d.agent_id}</span>
                      {d.agent_name && <span className="ml-1 text-[#535966]">({d.agent_name})</span>}
                    </td>
                    <td className="py-2 px-3 font-mono text-[#1A1C21] max-w-[320px] truncate" title={d.filepath}>
                      {d.filepath}
                    </td>
                    <td className="py-2 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-[#FEF08A] text-[#854D0E] font-semibold text-[10.5px]">
                        {d.severity || 'HIGH'}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded border text-[10.5px] font-semibold uppercase ${statusBadgeStyle(
                          d.status
                        )}`}
                      >
                        {d.status}
                      </span>
                      {isPending && typeof d.age_secs === 'number' && (
                        <span className="ml-1.5 text-[10.5px] font-mono text-[#535966]">
                          ({Math.round(d.age_secs / 60)}m)
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      {isPending && canWrite ? (
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => resolveDecision(d, 'quarantine')}
                            className="px-2 py-1 rounded border border-[#BD271E] bg-[#BD271E] text-white hover:bg-[#9E1F18] text-[11px] font-semibold cursor-pointer disabled:opacity-50"
                          >
                            Karantina (Approve)
                          </button>
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => resolveDecision(d, 'false_positive')}
                            className="px-2 py-1 rounded border border-[#D3DAE6] bg-white text-[#535966] hover:bg-[#FAFBFD] text-[11px] font-medium cursor-pointer disabled:opacity-50"
                          >
                            False Positive
                          </button>
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => resolveDecision(d, 'acknowledged')}
                            className="px-2 py-1 rounded border border-[#B8D5E5] bg-[#F0F7FC] text-[#006BB4] hover:bg-[#E1EFF8] text-[11px] font-medium cursor-pointer disabled:opacity-50"
                          >
                            Acknowledge
                          </button>
                        </div>
                      ) : (
                        <span className="text-[11px] text-[#535966] font-mono">
                          {d.action ? `${d.action} (${d.by || 'analis'})` : '-'}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
