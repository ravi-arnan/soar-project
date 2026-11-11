'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Server,
  Terminal,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  RefreshCw,
  Clock,
  ShieldCheck,
  ArrowRight,
  Monitor,
  Laptop,
  CheckSquare,
  XSquare,
} from 'lucide-react';
import { formatWazuhTime } from '@/lib/fleet';

export interface EnrollmentRequest {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  ip: string;
  status: 'pending' | 'approved' | 'rejected';
  agent_id: string | null;
  created_at: string;
  updated_at: string | null;
  approved_by: string | null;
}

interface AgentDeploymentViewProps {
  onBackToAgents?: () => void;
  userRole?: string;
}

export function AgentDeploymentView({ onBackToAgents, userRole = 'admin' }: AgentDeploymentViewProps) {
  const [targetOs, setTargetOs] = useState<'linux' | 'windows'>('linux');
  const [copied, setCopied] = useState(false);
  const [requests, setRequests] = useState<EnrollmentRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Modal approve & reject state
  const [selectedReq, setSelectedReq] = useState<EnrollmentRequest | null>(null);
  const [rejectTarget, setRejectTarget] = useState<EnrollmentRequest | null>(null);
  const [customName, setCustomName] = useState('');
  const [customId, setCustomId] = useState('');
  const [isApproving, setIsApproving] = useState(false);
  const [isRejecting, setIsRejecting] = useState(false);

  // Host origin detection
  const [origin] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.location.origin;
    }
    return 'https://soar.raviarnan.dev';
  });

  const linuxCommand = `curl -sSL ${origin}/api/enroll/script?os=linux | sudo bash`;
  const windowsCommand = `irm ${origin}/api/enroll/script?os=windows | iex`;
  const activeCommand = targetOs === 'linux' ? linuxCommand : windowsCommand;

  const fetchRequests = useCallback(async () => {
    try {
      const res = await fetch('/api/enroll');
      if (res.status === 401) {
        setError('Sesi dashboard belum aktif.');
        return;
      }
      if (res.status === 403) {
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
  }, []);

  useEffect(() => {
    let ignore = false;
    async function load() {
      try {
        const res = await fetch('/api/enroll');
        if (ignore) return;
        if (res.status === 401) {
          setError('Sesi dashboard belum aktif.');
          return;
        }
        if (res.status === 403) {
          setError('Hanya Admin dan Analyst yang dapat melihat antrean persetujuan agent.');
          return;
        }
        const data = await res.json();
        if (ignore) return;
        if (!res.ok) {
          setError(data.error || 'Gagal memuat antrean persetujuan.');
        } else {
          setRequests(data.requests || []);
        }
      } catch (err) {
        if (!ignore) {
          setError(`Kesalahan jaringan: ${err instanceof Error ? err.message : String(err)}`);
        }
      } finally {
        if (!ignore) {
          setLoading(false);
        }
      }
    }
    load();
    const timer = setInterval(() => {
      fetchRequests();
    }, 6000);
    return () => {
      ignore = true;
      clearInterval(timer);
    };
  }, [fetchRequests]);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(activeCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

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
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white border border-[#D3DAE6] rounded p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-[#E8F3FA] rounded-md text-[#006BB4]">
                <Server className="w-5 h-5" />
              </div>
              <h2 className="text-xl font-bold text-[#1A1C21]">
                Automated Agent Deployment &amp; Approval Portal
              </h2>
            </div>
            <p className="text-[13px] text-[#5A626F] mt-1.5 max-w-3xl leading-relaxed">
              Pemasangan agent otomatis tanpa konfigurasi manual di sisi klien. Pengguna di workstation
              cukup mengeksekusi 1 baris perintah installer, kemudian Administrator menyetujui (Approve)
              permohonan di bawah untuk langsung mengaktifkan perlindungan telemetri SOAR.
            </p>
          </div>
          {onBackToAgents && (
            <button
              onClick={onBackToAgents}
              className="h-9 px-4 border border-[#D3DAE6] hover:bg-[#F5F7FA] text-[#1A1C21] rounded text-[13px] font-medium transition-colors"
            >
              Kembali ke Daftar Agents
            </button>
          )}
        </div>

        {/* Notifications */}
        {error && (
          <div className="mt-4 p-3 bg-[#FDF3F2] border border-[#F5C2C0] rounded flex items-center gap-2.5 text-[12px] text-[#BD271E]">
            <XCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {successMsg && (
          <div className="mt-4 p-3 bg-[#E6F6F4] border border-[#A3E5DD] rounded flex items-center gap-2.5 text-[12px] text-[#00A389]">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}
      </div>

      {/* 4 Steps Visual Guide */}
      <div className="bg-white border border-[#D3DAE6] rounded p-5">
        <h3 className="text-[14px] font-bold text-[#1A1C21] flex items-center gap-2 mb-4">
          <ShieldCheck className="w-4 h-4 text-[#006BB4]" />
          <span>Alur Kerja Pemasangan Agent (Zero-Configuration &amp; Instant Approval)</span>
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-3.5 bg-[#F8FAFC] border border-[#E1E6EB] rounded">
            <div className="flex items-center gap-2 text-[12px] font-bold text-[#006BB4] mb-1">
              <span className="w-5 h-5 rounded-full bg-[#006BB4] text-white flex items-center justify-center text-[10px]">1</span>
              <span>Pilih OS Target</span>
            </div>
            <p className="text-[11px] text-[#5A626F]">
              Pilih Linux atau Windows di bawah untuk mendapatkan perintah instalasi khusus.
            </p>
          </div>

          <div className="p-3.5 bg-[#F8FAFC] border border-[#E1E6EB] rounded">
            <div className="flex items-center gap-2 text-[12px] font-bold text-[#006BB4] mb-1">
              <span className="w-5 h-5 rounded-full bg-[#006BB4] text-white flex items-center justify-center text-[10px]">2</span>
              <span>Eksekusi Perintah</span>
            </div>
            <p className="text-[11px] text-[#5A626F]">
              Jalankan perintah 1-baris pada terminal workstation klien dengan hak akses administrator.
            </p>
          </div>

          <div className="p-3.5 bg-[#F8FAFC] border border-[#E1E6EB] rounded">
            <div className="flex items-center gap-2 text-[12px] font-bold text-[#006BB4] mb-1">
              <span className="w-5 h-5 rounded-full bg-[#006BB4] text-white flex items-center justify-center text-[10px]">3</span>
              <span>Antrean Masuk</span>
            </div>
            <p className="text-[11px] text-[#5A626F]">
              Workstation otomatis terdaftar pada tabel antrean di bawah dengan status Pending.
            </p>
          </div>

          <div className="p-3.5 bg-[#F8FAFC] border border-[#E1E6EB] rounded">
            <div className="flex items-center gap-2 text-[12px] font-bold text-[#00A389] mb-1">
              <span className="w-5 h-5 rounded-full bg-[#00A389] text-white flex items-center justify-center text-[10px]">4</span>
              <span>Approve &amp; Aktif</span>
            </div>
            <p className="text-[11px] text-[#5A626F]">
              Klik tombol Approve. Layanan agent di workstation seketika aktif dan langsung terhubung.
            </p>
          </div>
        </div>
      </div>

      {/* Installer Command Generator */}
      <div className="bg-white border border-[#D3DAE6] rounded p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-[#006BB4]" />
            <h3 className="text-[14px] font-bold text-[#1A1C21]">Perintah Instalasi Satu Baris (One-Line Command)</h3>
          </div>
          <div className="flex items-center gap-1 bg-[#F5F7FA] p-1 rounded border border-[#D3DAE6]">
            <button
              onClick={() => setTargetOs('linux')}
              className={`px-3 py-1 text-[12px] font-semibold rounded flex items-center gap-1.5 transition-colors ${
                targetOs === 'linux' ? 'bg-white shadow text-[#006BB4]' : 'text-[#5A626F] hover:text-[#1A1C21]'
              }`}
            >
              <Monitor className="w-3.5 h-3.5" />
              <span>Linux (Bash)</span>
            </button>
            <button
              onClick={() => setTargetOs('windows')}
              className={`px-3 py-1 text-[12px] font-semibold rounded flex items-center gap-1.5 transition-colors ${
                targetOs === 'windows' ? 'bg-white shadow text-[#006BB4]' : 'text-[#5A626F] hover:text-[#1A1C21]'
              }`}
            >
              <Laptop className="w-3.5 h-3.5" />
              <span>Windows (PowerShell)</span>
            </button>
          </div>
        </div>

        <div className="bg-[#1E293B] text-white p-4 rounded-md font-mono text-[12px] flex items-center justify-between gap-4 overflow-x-auto">
          <span className="select-all text-[#38BDF8]">{activeCommand}</span>
          <button
            onClick={copyToClipboard}
            className="px-3 py-1.5 bg-[#334155] hover:bg-[#475569] text-white rounded text-[11px] font-sans font-medium flex items-center gap-1.5 shrink-0 transition-colors cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#4ADE80]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Tersalin' : 'Salin Perintah'}</span>
          </button>
        </div>
        <p className="text-[11px] text-[#8A94A6] mt-2">
          {targetOs === 'linux'
            ? 'Mendukung distribusi Debian, Ubuntu, CentOS, Fedora, Arch, dan NixOS. Mengharuskan hak akses root.'
            : 'Buka PowerShell sebagai Administrator (Run as Administrator) lalu tempel perintah di atas.'}
        </p>
      </div>

      {/* Pending Approvals Table */}
      <div className="bg-white border border-[#D3DAE6] rounded p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <h3 className="text-[14px] font-bold text-[#1A1C21]">
              Antrean Persetujuan Pendaftaran ({pendingRequests.length})
            </h3>
            {pendingRequests.length > 0 && (
              <span className="px-2 py-0.5 bg-[#FDF3F2] text-[#BD271E] font-bold text-[11px] rounded-full border border-[#F5C2C0] animate-pulse">
                {pendingRequests.length} Memerlukan Persetujuan
              </span>
            )}
          </div>
          <button
            onClick={() => fetchRequests()}
            className="h-8 px-3 border border-[#D3DAE6] hover:bg-[#F5F7FA] text-[#1A1C21] rounded text-[12px] font-medium flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Perbarui Antrean</span>
          </button>
        </div>

        <div className="overflow-x-auto border border-[#EBEFF5] rounded">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F] font-semibold">
                <th className="py-2.5 px-3">Waktu Request</th>
                <th className="py-2.5 px-3">Hostname Workstation</th>
                <th className="py-2.5 px-3">Sistem Operasi</th>
                <th className="py-2.5 px-3">Arsitektur</th>
                <th className="py-2.5 px-3">IP Pengirim</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Aksi Persetujuan</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEFF5]">
              {loading && requests.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#5A626F]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#006BB4]" />
                      <span>Memuat antrean persetujuan agent...</span>
                    </div>
                  </td>
                </tr>
              ) : pendingRequests.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#8A94A6]">
                    <div className="flex flex-col items-center justify-center gap-1.5">
                      <CheckCircle2 className="w-6 h-6 text-[#00A389]" />
                      <span className="font-medium text-[#1A1C21]">Tidak ada permohonan yang menunggu persetujuan.</span>
                      <span className="text-[11px] text-[#8A94A6]">
                        Jalankan perintah instalasi di atas pada workstation baru untuk mendaftarkan endpoint.
                      </span>
                    </div>
                  </td>
                </tr>
              ) : (
                pendingRequests.map((req) => (
                  <tr key={req.id} className="hover:bg-[#F8FAFC] transition-colors">
                    <td className="py-2.5 px-3 text-[#5A626F] font-mono text-[11px]">
                      {formatWazuhTime(req.created_at)}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-[#1A1C21]">
                      {req.hostname}
                    </td>
                    <td className="py-2.5 px-3 uppercase text-[11px] font-medium text-[#5A626F]">
                      {req.os}
                    </td>
                    <td className="py-2.5 px-3 text-[11px] font-mono text-[#5A626F]">
                      {req.arch}
                    </td>
                    <td className="py-2.5 px-3 text-[11px] font-mono text-[#5A626F]">
                      {req.ip || '-'}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold uppercase bg-[#FEF3D6] text-[#B58500]">
                        <Clock className="w-3 h-3" />
                        <span>Pending</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      {userRole === 'admin' ? (
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleOpenApproveModal(req)}
                            className="px-2.5 py-1 bg-[#00A389] hover:bg-[#008A74] text-white rounded text-[11px] font-medium flex items-center gap-1 shadow-sm transition-colors cursor-pointer"
                          >
                            <CheckSquare className="w-3 h-3" />
                            <span>Setujui (Approve)</span>
                          </button>
                          <button
                            onClick={() => handleReject(req)}
                            className="px-2.5 py-1 bg-[#FDF3F2] hover:bg-[#FBE8E7] text-[#BD271E] border border-[#F5C2C0] rounded text-[11px] font-medium flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            <XSquare className="w-3 h-3" />
                            <span>Tolak</span>
                          </button>
                        </div>
                      ) : (
                        <span className="text-[11px] text-[#8A94A6]">Hanya Admin</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* History of Past Requests */}
      {pastRequests.length > 0 && (
        <div className="bg-white border border-[#D3DAE6] rounded p-5">
          <h3 className="text-[14px] font-bold text-[#1A1C21] mb-3">
            Riwayat Persetujuan Sebelumnya ({pastRequests.length})
          </h3>
          <div className="overflow-x-auto border border-[#EBEFF5] rounded">
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F] font-semibold">
                  <th className="py-2 px-3">Hostname</th>
                  <th className="py-2 px-3">OS</th>
                  <th className="py-2 px-3">Agent ID Terbit</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">Disetujui Oleh</th>
                  <th className="py-2 px-3">Waktu Selesai</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EBEFF5]">
                {pastRequests.slice(0, 10).map((r) => (
                  <tr key={r.id} className="text-[#5A626F]">
                    <td className="py-2 px-3 font-medium text-[#1A1C21]">{r.hostname}</td>
                    <td className="py-2 px-3 uppercase text-[11px]">{r.os}</td>
                    <td className="py-2 px-3 font-mono font-semibold text-[#006BB4]">{r.agent_id || '-'}</td>
                    <td className="py-2 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          r.status === 'approved'
                            ? 'bg-[#E6F6F4] text-[#00A389]'
                            : 'bg-[#FDF3F2] text-[#BD271E]'
                        }`}
                      >
                        {r.status === 'approved' ? 'Disetujui' : 'Ditolak'}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-[11px]">{r.approved_by || '-'}</td>
                    <td className="py-2 px-3 font-mono text-[11px]">{r.updated_at ? formatWazuhTime(r.updated_at) : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal Konfirmasi Persetujuan (Approve Modal) */}
      {selectedReq && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
          <div className="bg-white rounded border border-[#D3DAE6] shadow-2xl max-w-md w-full p-6 animate-in fade-in duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-[#E1E6EB]">
              <h3 className="text-base font-bold text-[#1A1C21] flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#00A389]" />
                <span>Konfirmasi Persetujuan Agent</span>
              </h3>
              <button
                onClick={() => setSelectedReq(null)}
                className="p-1 rounded text-[#5A626F] hover:bg-[#F5F7FA]"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-4 space-y-3 text-[13px]">
              <div className="p-3 bg-[#F8FAFC] rounded border border-[#E1E6EB] text-[12px] space-y-1">
                <div><span className="text-[#8A94A6]">Hostname: </span><span className="font-semibold text-[#1A1C21]">{selectedReq.hostname}</span></div>
                <div><span className="text-[#8A94A6]">Sistem Operasi: </span><span className="font-semibold text-[#1A1C21]">{selectedReq.os} ({selectedReq.arch})</span></div>
                <div><span className="text-[#8A94A6]">IP Address: </span><span className="font-mono text-[#1A1C21]">{selectedReq.ip || 'Local/LAN'}</span></div>
              </div>

              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">Nama Tampilan Agent (Display Name)</label>
                <input
                  type="text"
                  value={customName}
                  onChange={(e) => setCustomName(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                  placeholder="misal: workstation-finance-01"
                />
              </div>

              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">
                  Agent ID Kustom (Opsional, kosongkan untuk auto-generate)
                </label>
                <input
                  type="text"
                  value={customId}
                  onChange={(e) => setCustomId(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                  placeholder="misal: 004 atau otomatis"
                />
                <span className="text-[11px] text-[#8A94A6]">
                  Jika dikosongkan, sistem otomatis memberikan nomor urut berikutnya.
                </span>
              </div>

              <div className="pt-3 border-t border-[#E1E6EB] flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedReq(null)}
                  className="px-3 py-1.5 border border-[#D3DAE6] rounded text-[#5A626F] hover:bg-[#F5F7FA]"
                >
                  Batal
                </button>
                <button
                  type="button"
                  onClick={handleApprove}
                  disabled={isApproving}
                  className="px-4 py-1.5 bg-[#00A389] hover:bg-[#008A74] text-white rounded font-medium flex items-center gap-1.5 shadow-sm"
                >
                  {isApproving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ArrowRight className="w-3.5 h-3.5" />}
                  <span>Setujui &amp; Aktifkan</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Reject Confirmation Modal */}
      {rejectTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="bg-white border border-[#D3DAE6] rounded w-full max-w-md p-5 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-full bg-[#FDF3F2] text-[#BD271E] shrink-0">
                <XCircle className="w-5 h-5" />
              </div>
              <div className="flex-1">
                <h3 className="text-[14px] font-bold text-[#1A1C21]">
                  Tolak Pendaftaran Agent
                </h3>
                <p className="text-[12px] text-[#5A626F] mt-1 leading-relaxed">
                  Apakah Anda yakin ingin menolak permohonan pendaftaran dari host{' '}
                  <strong className="text-[#1A1C21] font-mono">{rejectTarget.hostname}</strong>?
                </p>

                <div className="mt-3 p-2.5 rounded bg-[#F8FAFC] border border-[#E2E8F0] text-[11px] font-mono space-y-1">
                  <div><span className="text-[#8A94A6]">IP Address:</span> {rejectTarget.ip}</div>
                  <div><span className="text-[#8A94A6]">OS / Arch:</span> {rejectTarget.os} ({rejectTarget.arch})</div>
                  <div><span className="text-[#8A94A6]">Request ID:</span> {rejectTarget.id}</div>
                </div>

                <div className="flex items-center justify-end gap-2.5 mt-5">
                  <button
                    type="button"
                    onClick={() => setRejectTarget(null)}
                    className="px-3 py-1.5 border border-[#D3DAE6] rounded text-[12px] font-medium text-[#5A626F] hover:bg-[#F5F7FA] transition"
                  >
                    Batal
                  </button>
                  <button
                    type="button"
                    onClick={executeReject}
                    disabled={isRejecting}
                    className="px-3 py-1.5 rounded text-[12px] font-semibold text-white bg-[#BD271E] hover:bg-[#9E1F18] transition flex items-center gap-1.5"
                  >
                    {isRejecting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
                    <span>Tolak Permohonan</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
