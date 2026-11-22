'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import { formatWazuhTime } from '@/lib/fleet';
import { AgentInstallerPanel } from './AgentInstallerPanel';
import {
  WuiBadge,
  WuiCallOut,
  WuiHealth,
  WuiModal,
  WuiPageHeader,
  WuiPanel,
} from '../wui/WuiPrimitives';

export interface EnrollmentRequest {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  ip: string;
  status: 'pending' | 'approved' | 'rejected' | 'revoked';
  agent_id: string | null;
  created_at: string;
  updated_at: string | null;
  approved_by: string | null;
}

interface AgentDeploymentViewProps {
  onBackToAgents?: () => void;
  userRole?: string;
}

export function AgentDeploymentView({ onBackToAgents, userRole = 'viewer' }: AgentDeploymentViewProps) {
  const [requests, setRequests] = useState<EnrollmentRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [authBlocked, setAuthBlocked] = useState(false);

  const [selectedReq, setSelectedReq] = useState<EnrollmentRequest | null>(null);
  const [rejectTarget, setRejectTarget] = useState<EnrollmentRequest | null>(null);
  const [customName, setCustomName] = useState('');
  const [customId, setCustomId] = useState('');
  const [isApproving, setIsApproving] = useState(false);
  const [isRejecting, setIsRejecting] = useState(false);

  const [installerOrigin, setInstallerOrigin] = useState('https://soar-agent.example.com');

  useEffect(() => {
    const fallbackOrigin =
      typeof window !== 'undefined' && window.location.origin
        ? window.location.origin
        : 'https://soar-agent.example.com';
    fetch('/api/config/public', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        setInstallerOrigin(d?.publicEnrollUrl ? String(d.publicEnrollUrl) : fallbackOrigin);
      })
      .catch(() => {
        setInstallerOrigin(fallbackOrigin);
      });
  }, []);

  const fetchRequests = useCallback(async () => {
    if (authBlocked) return;
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
    try {
      const res = await fetch('/api/enroll');
      if (res.status === 401) {
        setAuthBlocked(true);
        setError('Sesi dashboard belum aktif.');
        return;
      }
      if (res.status === 403) {
        setAuthBlocked(true);
        setError('Hanya Admin dan Analyst yang dapat melihat antrean persetujuan agent.');
        return;
      }
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Gagal memuat antrean persetujuan.');
        return;
      }
      setRequests(data.requests || []);
    } catch (err) {
      setError(`Kesalahan jaringan: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [authBlocked]);

  useEffect(() => {
    if (authBlocked) return;
    let cancelled = false;
    const pull = async () => {
      if (cancelled) return;
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      try {
        const res = await fetch('/api/enroll');
        if (cancelled) return;
        if (res.status === 401) {
          setAuthBlocked(true);
          setError('Sesi dashboard belum aktif.');
          return;
        }
        if (res.status === 403) {
          setAuthBlocked(true);
          setError('Hanya Admin dan Analyst yang dapat melihat antrean persetujuan agent.');
          return;
        }
        const data = await res.json();
        if (cancelled) return;
        if (!res.ok) {
          setError(data.error || 'Gagal memuat antrean persetujuan.');
          return;
        }
        setRequests(data.requests || []);
      } catch (err) {
        if (!cancelled) {
          setError(`Kesalahan jaringan: ${err instanceof Error ? err.message : String(err)}`);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void pull();
    const timer = setInterval(() => {
      void pull();
    }, 6000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [authBlocked]);

  const handleOpenApproveModal = (req: EnrollmentRequest) => {
    setSelectedReq(req);
    setCustomName(`workstation-${req.hostname}`);
    setCustomId('');
  };

  const handleApprove = async () => {
    if (!selectedReq) return;
    setIsApproving(true);
    setError(null);
    try {
      const res = await fetch('/api/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'approve',
          request_id: selectedReq.id,
          agent_name: customName,
          agent_id: customId || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setError(data.error || 'Gagal menyetujui permohonan.');
        setIsApproving(false);
        return;
      }
      setSuccessMsg(`Workstation '${selectedReq.hostname}' berhasil disetujui (Agent ID: ${data.agent.agent_id}). Agent kini aktif.`);
      setSelectedReq(null);
      fetchRequests();
    } catch (err) {
      setError(`Gagal memproses persetujuan: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsApproving(false);
    }
  };

  const handleReject = (req: EnrollmentRequest) => {
    setRejectTarget(req);
  };

  const executeReject = async () => {
    if (!rejectTarget) return;
    setIsRejecting(true);
    setError(null);
    try {
      const res = await fetch('/api/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'reject',
          request_id: rejectTarget.id,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setError(data.error || 'Gagal menolak permohonan.');
        setIsRejecting(false);
        return;
      }
      setSuccessMsg(`Permohonan dari host '${rejectTarget.hostname}' telah ditolak.`);
      setRejectTarget(null);
      fetchRequests();
    } catch (err) {
      setError(`Gagal menolak: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsRejecting(false);
    }
  };

  const pendingRequests = requests.filter((r) => r.status === 'pending');
  const pastRequests = requests.filter((r) => r.status !== 'pending');

  return (
    <div className="space-y-4">
      <WuiPageHeader
        title="Deploy new agent"
        description="Pemasangan baru & pembaruan agent endpoint SOAR tanpa konfigurasi manual. Jalankan perintah di workstation target lalu pantau status service atau setujui pendaftaran baru pada antrean di bawah."
        actions={
          onBackToAgents && (
            <button
              type="button"
              onClick={onBackToAgents}
              className="h-8 px-3 border border-[#D3DAE6] bg-white hover:bg-[#FAFBFD] text-[#1A1C21] rounded-[4px] text-[12px] font-medium transition-colors cursor-pointer"
            >
              Kembali ke Agents
            </button>
          )
        }
      />

      {error && <WuiCallOut tone="danger">{error}</WuiCallOut>}
      {successMsg && <WuiCallOut tone="success">{successMsg}</WuiCallOut>}

      <AgentInstallerPanel installerOrigin={installerOrigin} />

      {/* Pending Approvals Table */}
      <WuiPanel
        title={
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold text-[#1A1C21]">
              Pending agent approvals ({pendingRequests.length})
            </span>
            {pendingRequests.length > 0 && (
              <WuiBadge tone="warning">{pendingRequests.length} menunggu</WuiBadge>
            )}
          </div>
        }
        accentColor="#FEC514"
        right={
          <button
            type="button"
            onClick={() => fetchRequests()}
            className="h-7 px-2.5 border border-[#D3DAE6] bg-white hover:bg-[#FAFBFD] text-[#1A1C21] rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <WuiIcon type="refresh" size="s" className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        }
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-[#D3DAE6] text-[#535966] font-semibold text-[12px]">
                <th className="py-2.5 px-4">Waktu Request</th>
                <th className="py-2.5 px-4">Hostname</th>
                <th className="py-2.5 px-4">OS</th>
                <th className="py-2.5 px-4">Arch</th>
                <th className="py-2.5 px-4">IP Pengirim</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E9EDF3]">
              {loading && requests.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#535966]">
                    <div className="flex items-center justify-center gap-2">
                      <WuiIcon type="refresh" size="m" className="animate-spin text-[#006BB4]" />
                      <span>Memuat antrean persetujuan agent...</span>
                    </div>
                  </td>
                </tr>
              ) : pendingRequests.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#535966]">
                    <div className="flex flex-col items-center justify-center gap-1">
                      <WuiIcon type="checkInCircleFilled" size="m" className="text-[#017D73]" />
                      <span className="font-medium text-[#1A1C21]">
                        Tidak ada permohonan yang menunggu persetujuan.
                      </span>
                      <span className="text-[11px] text-[#69707D]">
                        Jalankan perintah instalasi pada workstation baru untuk mendaftarkan endpoint.
                      </span>
                    </div>
                  </td>
                </tr>
              ) : (
                pendingRequests.map((req) => (
                  <tr key={req.id} className="hover:bg-[#FAFBFD] transition-colors">
                    <td className="py-2.5 px-4 text-[#535966] font-mono tabular-nums text-[11px]">
                      {formatWazuhTime(req.created_at)}
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-[#1A1C21]">{req.hostname}</td>
                    <td className="py-2.5 px-4 uppercase text-[11px] text-[#535966]">{req.os}</td>
                    <td className="py-2.5 px-4 text-[11px] font-mono text-[#535966]">{req.arch}</td>
                    <td className="py-2.5 px-4 text-[11px] font-mono tabular-nums text-[#535966]">
                      {req.ip || '-'}
                    </td>
                    <td className="py-2.5 px-4">
                      <WuiHealth tone="warning">Pending</WuiHealth>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {userRole === 'admin' ? (
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleOpenApproveModal(req)}
                            className="px-2.5 py-1 bg-[#017D73] hover:bg-[#005E58] text-white rounded-[4px] text-[11px] font-medium inline-flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            <WuiIcon type="check" size="xs" />
                            <span>Approve</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => handleReject(req)}
                            className="px-2.5 py-1 bg-white hover:bg-[#FBECEB] text-[#BD271E] border border-[#F3C5C3] rounded-[4px] text-[11px] font-medium inline-flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            <WuiIcon type="cross" size="xs" />
                            <span>Reject</span>
                          </button>
                        </div>
                      ) : (
                        <span className="text-[11px] text-[#69707D]">Admin only</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </WuiPanel>

      {/* History of Past Requests */}
      {pastRequests.length > 0 && (
        <WuiPanel
          title={`Enrollment history (${pastRequests.length})`}
          accentColor="#007871"
          bodyClassName="p-0"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-[#D3DAE6] text-[#535966] font-semibold text-[12px]">
                  <th className="py-2 px-4">Hostname</th>
                  <th className="py-2 px-4">OS</th>
                  <th className="py-2 px-4">Agent ID</th>
                  <th className="py-2 px-4">Status</th>
                  <th className="py-2 px-4">Approved by</th>
                  <th className="py-2 px-4">Completed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E9EDF3]">
                {pastRequests.slice(0, 10).map((r) => (
                  <tr key={r.id} className="hover:bg-[#FAFBFD] text-[#535966]">
                    <td className="py-2 px-4 font-medium text-[#1A1C21]">{r.hostname}</td>
                    <td className="py-2 px-4 uppercase text-[11px]">{r.os}</td>
                    <td className="py-2 px-4 font-mono font-semibold text-[#006BB4]">
                      {r.agent_id || '-'}
                    </td>
                    <td className="py-2 px-4">
                      <WuiHealth tone={r.status === 'approved' ? 'success' : 'danger'}>
                        {r.status === 'approved'
                          ? 'Approved'
                          : r.status === 'revoked'
                          ? 'Revoked'
                          : 'Rejected'}
                      </WuiHealth>
                    </td>
                    <td className="py-2 px-4 text-[11px]">{r.approved_by || '-'}</td>
                    <td className="py-2 px-4 font-mono tabular-nums text-[11px]">
                      {r.updated_at ? formatWazuhTime(r.updated_at) : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </WuiPanel>
      )}

      {/* Modal Konfirmasi Persetujuan (Approve Modal) */}
      {selectedReq && (
        <WuiModal
          title="Konfirmasi Persetujuan Agent"
          onClose={() => setSelectedReq(null)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setSelectedReq(null)}
                className="px-3 py-1.5 border border-[#D3DAE6] rounded-[4px] text-[12px] text-[#535966] hover:bg-[#F5F7FA] cursor-pointer"
              >
                Batal
              </button>
              <button
                type="button"
                onClick={handleApprove}
                disabled={isApproving}
                className="px-3.5 py-1.5 bg-[#017D73] hover:bg-[#005E58] text-white rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {isApproving ? (
                  <WuiIcon type="refresh" size="s" className="animate-spin" />
                ) : (
                  <WuiIcon type="arrowRight" size="s" />
                )}
                <span>Setujui &amp; Aktifkan</span>
              </button>
            </>
          }
        >
          <div className="space-y-3 text-[12.5px]">
            <div className="p-3 bg-[#FAFBFD] rounded-[4px] border border-[#D3DAE6] text-[12px] space-y-1">
              <div>
                <span className="text-[#69707D]">Hostname: </span>
                <span className="font-semibold text-[#1A1C21]">{selectedReq.hostname}</span>
              </div>
              <div>
                <span className="text-[#69707D]">Sistem Operasi: </span>
                <span className="font-semibold text-[#1A1C21]">
                  {selectedReq.os} ({selectedReq.arch})
                </span>
              </div>
              <div>
                <span className="text-[#69707D]">IP Address: </span>
                <span className="font-mono text-[#1A1C21]">{selectedReq.ip || 'Local/LAN'}</span>
              </div>
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">
                Nama Tampilan Agent (Display Name)
              </label>
              <input
                type="text"
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
                placeholder="workstation-finance-01"
              />
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">
                Agent ID Kustom (Opsional)
              </label>
              <input
                type="text"
                value={customId}
                onChange={(e) => setCustomId(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px] font-mono"
                placeholder="004 (kosongkan untuk otomatis)"
              />
            </div>
          </div>
        </WuiModal>
      )}

      {/* Reject Confirmation Modal */}
      {rejectTarget && (
        <WuiModal
          title="Tolak Pendaftaran Agent"
          onClose={() => setRejectTarget(null)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setRejectTarget(null)}
                className="px-3 py-1.5 border border-[#D3DAE6] rounded-[4px] text-[12px] font-medium text-[#535966] hover:bg-[#F5F7FA] cursor-pointer"
              >
                Batal
              </button>
              <button
                type="button"
                onClick={executeReject}
                disabled={isRejecting}
                className="px-3 py-1.5 rounded-[4px] text-[12px] font-semibold text-white bg-[#BD271E] hover:bg-[#9E1F18] flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {isRejecting ? <WuiIcon type="refresh" size="s" className="animate-spin" /> : null}
                <span>Tolak Permohonan</span>
              </button>
            </>
          }
        >
          <div className="space-y-3">
            <p className="text-[12px] text-[#535966] leading-relaxed">
              Apakah Anda yakin ingin menolak permohonan pendaftaran dari host{' '}
              <strong className="text-[#1A1C21] font-mono">{rejectTarget.hostname}</strong>?
            </p>
            <div className="p-2.5 rounded-[4px] bg-[#FAFBFD] border border-[#D3DAE6] text-[11px] font-mono space-y-1">
              <div>
                <span className="text-[#69707D]">IP Address:</span> {rejectTarget.ip}
              </div>
              <div>
                <span className="text-[#69707D]">OS / Arch:</span> {rejectTarget.os} ({rejectTarget.arch})
              </div>
              <div>
                <span className="text-[#69707D]">Request ID:</span> {rejectTarget.id}
              </div>
            </div>
          </div>
        </WuiModal>
      )}
    </div>
  );
}
