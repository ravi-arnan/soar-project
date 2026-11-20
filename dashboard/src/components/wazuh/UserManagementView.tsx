'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import { formatWazuhTime } from '@/lib/fleet';
import { WuiBadge, WuiCallOut, WuiModal, WuiPageHeader, WuiPanel } from '../wui/WuiPrimitives';

export interface UserItem {
  id: string;
  username: string;
  role: 'admin' | 'analyst' | 'viewer';
  email: string;
  name: string;
  created_at: string;
  last_login_at: string | null;
  active: boolean;
}

export interface CloudflareSyncInfo {
  configured: boolean;
  synced?: boolean;
  status?: string;
  last_status?: string;
  detail?: string;
  last_detail?: string;
  policy_name?: string;
  policy_id?: string;
  active_emails_count?: number;
  emails_count?: number;
  last_synced_at?: string | null;
  synced_at?: string | null;
}

const PERMISSIONS = [
  { action: 'Monitoring Dashboard, Security Events, Network Map & FIM', admin: true, analyst: true, viewer: true },
  { action: 'Lihat Detail Telemetri Agent & Hasil Sintesis Threat Intel', admin: true, analyst: true, viewer: true },
  { action: 'Eksekusi Active Response (Karantina File & Sinkhole Domain)', admin: true, analyst: true, viewer: false },
  { action: 'Jalankan On-Demand FIM Scan pada Endpoint', admin: true, analyst: true, viewer: false },
  { action: 'Manajemen API Keys Mesin (Penerbitan & Pencabutan Token)', admin: true, analyst: false, viewer: false },
  { action: 'Manajemen Pengguna (User Management, Tambah/Edit Role, Reset Sandi)', admin: true, analyst: false, viewer: false },
];

export function UserManagementView() {
  const [users, setUsers] = useState<UserItem[]>([]);
  const [cfSync, setCfSync] = useState<CloudflareSyncInfo | null>(null);
  const [isSyncingCf, setIsSyncingCf] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [warningMsg, setWarningMsg] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | 'admin' | 'analyst' | 'viewer'>('all');
  const [showMatrix, setShowMatrix] = useState(false);

  // Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserItem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<UserItem | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Form State
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formRole, setFormRole] = useState<'admin' | 'analyst' | 'viewer'>('viewer');
  const [formEmail, setFormEmail] = useState('');
  const [formName, setFormName] = useState('');
  const [formActive, setFormActive] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/users');
      if (res.status === 401) {
        setError('Sesi dashboard belum aktif. Silakan buka menu API Keys untuk verifikasi 2FA.');
        return;
      }
      if (res.status === 403) {
        setError('Akses ditolak: Hanya role Admin yang berwenang mengelola pengguna.');
        return;
      }
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Gagal memuat daftar pengguna.');
        return;
      }
      setUsers(data.users || []);
      if (data.cloudflare_sync) setCfSync(data.cloudflare_sync);
    } catch (err) {
      setError(`Kesalahan jaringan: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    async function loadInitial() {
      try {
        const res = await fetch('/api/users');
        if (ignore) return;
        if (res.status === 401) {
          setError('Sesi dashboard belum aktif. Silakan buka menu API Keys untuk verifikasi 2FA.');
          return;
        }
        if (res.status === 403) {
          setError('Akses ditolak: Hanya role Admin yang berwenang mengelola pengguna.');
          return;
        }
        const data = await res.json();
        if (ignore) return;
        if (!res.ok) {
          setError(data.error || 'Gagal memuat daftar pengguna.');
        } else {
          setUsers(data.users || []);
          if (data.cloudflare_sync) setCfSync(data.cloudflare_sync);
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
    loadInitial();
    return () => {
      ignore = true;
    };
  }, []);

  const showSuccess = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 5000);
  };

  const applySyncFeedback = (baseMsg: string, syncInfo?: CloudflareSyncInfo | null) => {
    if (!syncInfo) {
      showSuccess(baseMsg);
      return;
    }
    setCfSync(syncInfo);
    if (syncInfo.synced) {
      setWarningMsg(null);
      showSuccess(`${baseMsg} Cloudflare Access tersinkron (${syncInfo.emails_count ?? 0} email aktif).`);
    } else if (syncInfo.configured && syncInfo.status === 'error') {
      showSuccess(baseMsg);
      setWarningMsg(syncInfo.detail || 'Perubahan tersimpan di SOAR, tetapi gagal sinkron ke Cloudflare Access.');
    } else {
      showSuccess(baseMsg);
    }
  };

  const handleSyncCloudflare = async () => {
    setIsSyncingCf(true);
    setError(null);
    setWarningMsg(null);
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'sync_cloudflare' }),
      });
      const data = await res.json();
      if (data.cloudflare_sync) {
        setCfSync(data.cloudflare_sync);
      }
      if (!res.ok) {
        setWarningMsg(data.error || data.cloudflare_sync?.detail || 'Gagal menyinkronkan ke Cloudflare Access.');
        return;
      }
      if (data.cloudflare_sync?.synced) {
        showSuccess(data.cloudflare_sync.detail || 'Cloudflare Access berhasil disinkronkan.');
      } else {
        setWarningMsg(data.cloudflare_sync?.detail || 'Sinkronisasi Cloudflare Access belum dikonfigurasi.');
      }
    } catch (err) {
      setError(`Gagal sinkronisasi Cloudflare: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSyncingCf(false);
    }
  };

  const resetForm = () => {
    setFormUsername('');
    setFormPassword('');
    setFormRole('viewer');
    setFormEmail('');
    setFormName('');
    setFormActive(true);
    setSelectedUser(null);
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formUsername || !formPassword || !formEmail) {
      setError('Email Cloudflare Access, Username, dan Password wajib diisi');
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'create',
          username: formUsername,
          password: formPassword,
          role: formRole,
          email: formEmail,
          name: formName,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setError(data.error || 'Gagal membuat pengguna');
        setIsSubmitting(false);
        return;
      }
      applySyncFeedback(
        `Pengguna '${formUsername}' dengan role '${formRole}' berhasil ditambahkan.`,
        data.cloudflare_sync,
      );
      setIsCreateOpen(false);
      resetForm();
      fetchUsers();
    } catch (err) {
      setError(`Gagal menyimpan: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const payload: Record<string, unknown> = {
        action: 'update',
        id: selectedUser.id,
        role: formRole,
        name: formName,
        email: formEmail,
        active: formActive,
      };
      if (formPassword) {
        payload.password = formPassword;
      }
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setError(data.error || 'Gagal memperbarui pengguna');
        setIsSubmitting(false);
        return;
      }
      applySyncFeedback(`Pengguna '${selectedUser.username}' berhasil diperbarui.`, data.cloudflare_sync);
      setIsEditOpen(false);
      resetForm();
      fetchUsers();
    } catch (err) {
      setError(`Gagal memperbarui: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = (user: UserItem) => {
    setDeleteTarget(user);
  };

  const executeDelete = async () => {
    if (!deleteTarget) return;
    setIsDeleting(true);
    setError(null);
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete', id: deleteTarget.id }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setError(data.error || 'Gagal menghapus pengguna');
        setIsDeleting(false);
        return;
      }
      applySyncFeedback(`Pengguna '${deleteTarget.username}' berhasil dihapus.`, data.cloudflare_sync);
      setDeleteTarget(null);
      fetchUsers();
    } catch (err) {
      setError(`Gagal menghapus: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsDeleting(false);
    }
  };

  const openEditModal = (user: UserItem) => {
    setSelectedUser(user);
    setFormUsername(user.username);
    setFormRole(user.role);
    setFormEmail(user.email);
    setFormName(user.name);
    setFormActive(user.active);
    setFormPassword('');
    setIsEditOpen(true);
  };

  const filteredUsers = users.filter((u) => {
    const matchesSearch =
      u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.email.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = roleFilter === 'all' || u.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  const adminCount = users.filter((u) => u.role === 'admin').length;
  const analystCount = users.filter((u) => u.role === 'analyst').length;
  const viewerCount = users.filter((u) => u.role === 'viewer').length;

  return (
    <div className="space-y-4">
      <WuiPageHeader
        title="User Management &amp; RBAC"
        description="Manajemen akun personel SOC dan otorisasi berjenjang (Admin, Analyst, Viewer). Sesi login dipetakan dari header email Cloudflare Access."
        actions={
          <>
            <button
              type="button"
              onClick={handleSyncCloudflare}
              disabled={isSyncingCf}
              className="h-8 px-3 border border-[#D3DAE6] bg-white hover:bg-[#FAFBFD] text-[#1A1C21] rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
              title="Sinkronkan daftar email aktif ke Cloudflare Zero Trust Access Policy"
            >
              <WuiIcon type="bolt" size="s" className="text-[#006BB4]" />
              <span>{isSyncingCf ? 'Menyinkronkan...' : 'Sync Cloudflare'}</span>
            </button>
            <button
              type="button"
              onClick={() => fetchUsers()}
              className="h-8 px-3 border border-[#D3DAE6] bg-white hover:bg-[#FAFBFD] text-[#1A1C21] rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Refresh Data"
            >
              <WuiIcon type="refresh" size="s" className={loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
            <button
              type="button"
              onClick={() => {
                resetForm();
                setIsCreateOpen(true);
              }}
              className="h-8 px-3.5 bg-[#006BB4] hover:bg-[#00538C] text-white rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <WuiIcon type="user" size="s" />
              <span>Tambah Pengguna</span>
            </button>
          </>
        }
      />

      {error && <WuiCallOut tone="danger">{error}</WuiCallOut>}
      {warningMsg && <WuiCallOut tone="warning">{warningMsg}</WuiCallOut>}
      {successMsg && <WuiCallOut tone="success">{successMsg}</WuiCallOut>}

      {cfSync && (
        <div className="bg-white border border-[#D3DAE6] rounded-[4px] px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-[12px]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-[#1A1C21]">
              Cloudflare Access Auto-Sync
            </span>
            <span className="text-[#535966]">
              {!cfSync.configured
                ? 'Belum aktif: set CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, dan CLOUDFLARE_ACCESS_POLICY_ID di .env server.'
                : cfSync.detail ||
                  cfSync.last_detail ||
                  `Siap menyinkronkan ${cfSync.active_emails_count ?? cfSync.emails_count ?? 0} email aktif ke policy ${cfSync.policy_id || ''}.`}
            </span>
          </div>
          {(cfSync.synced_at || cfSync.last_synced_at) && (
            <span className="text-[11px] font-mono text-[#69707D]">
              Sync terakhir: {formatWazuhTime(cfSync.synced_at || cfSync.last_synced_at || '')}
            </span>
          )}
        </div>
      )}

      {/* WUI Unified Summary Bar */}
      <div className="bg-white border border-[#D3DAE6] rounded-[4px] divide-y md:divide-y-0 md:divide-x divide-[#E9EDF3] grid grid-cols-2 md:grid-cols-4">
        <div className="px-4 py-3">
          <div className="text-[12px] font-medium text-[#535966]">
            Total Pengguna
          </div>
          <div className="text-[22px] font-semibold font-mono tabular-nums text-[#1A1C21] mt-0.5">{users.length}</div>
          <div className="text-[11px] text-[#69707D] mt-0.5">Akun personel terdaftar</div>
        </div>

        <div className="px-4 py-3">
          <div className="text-[12px] font-medium text-[#535966]">
            Administrators
          </div>
          <div className="text-[22px] font-semibold font-mono tabular-nums text-[#006BB4] mt-0.5">{adminCount}</div>
          <div className="text-[11px] text-[#69707D] mt-0.5">Akses penuh &amp; API keys</div>
        </div>

        <div className="px-4 py-3">
          <div className="text-[12px] font-medium text-[#535966]">
            Security Analysts
          </div>
          <div className="text-[22px] font-semibold font-mono tabular-nums text-[#007871] mt-0.5">{analystCount}</div>
          <div className="text-[11px] text-[#69707D] mt-0.5">Mitigasi &amp; respons ancaman</div>
        </div>

        <div className="px-4 py-3">
          <div className="text-[12px] font-medium text-[#535966]">
            Auditors &amp; Viewers
          </div>
          <div className="text-[22px] font-semibold font-mono tabular-nums text-[#535966] mt-0.5">{viewerCount}</div>
          <div className="text-[11px] text-[#69707D] mt-0.5">Monitoring read-only</div>
        </div>
      </div>

      {/* Role Permission Matrix (Collapsible) */}
      <div className="bg-white border border-[#D3DAE6] rounded-[4px] overflow-hidden">
        <button
          type="button"
          onClick={() => setShowMatrix(!showMatrix)}
          className="w-full bg-[#FAFBFD] px-4 py-2.5 flex items-center justify-between text-left hover:bg-[#F0F4F8] transition-colors border-b border-[#E9EDF3] cursor-pointer"
        >
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold text-[#1A1C21]">Matriks Hak Akses Role (RBAC)</span>
            <span className="text-[11px] text-[#535966] font-normal">(6 kapabilitas operasional)</span>
          </div>
          <div className="flex items-center gap-1.5 text-[12px] text-[#006BB4] font-medium">
            <span>{showMatrix ? 'Sembunyikan' : 'Lihat Detail'}</span>
            <WuiIcon type={showMatrix ? 'arrowUp' : 'arrowDown'} size="m" />
          </div>
        </button>

        {showMatrix && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-[#D3DAE6] text-[#535966] text-[12px]">
                  <th className="py-2.5 px-4 font-semibold">Kapabilitas &amp; Hak Operasi</th>
                  <th className="py-2.5 px-4 font-semibold text-center w-28">Admin</th>
                  <th className="py-2.5 px-4 font-semibold text-center w-28">Analyst</th>
                  <th className="py-2.5 px-4 font-semibold text-center w-28">Viewer</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E9EDF3]">
                {PERMISSIONS.map((p, idx) => (
                  <tr key={idx} className="hover:bg-[#FAFBFD] transition-colors">
                    <td className="py-2 px-4 text-[#1A1C21] font-medium">{p.action}</td>
                    <td className="py-2 px-4 text-center">
                      {p.admin ? (
                        <WuiIcon type="check" size="m" className="text-[#017D73] mx-auto" />
                      ) : (
                        <WuiIcon type="minus" size="s" className="text-[#69707D] mx-auto" />
                      )}
                    </td>
                    <td className="py-2 px-4 text-center">
                      {p.analyst ? (
                        <WuiIcon type="check" size="m" className="text-[#017D73] mx-auto" />
                      ) : (
                        <WuiIcon type="minus" size="s" className="text-[#69707D] mx-auto" />
                      )}
                    </td>
                    <td className="py-2 px-4 text-center">
                      {p.viewer ? (
                        <WuiIcon type="check" size="m" className="text-[#017D73] mx-auto" />
                      ) : (
                        <WuiIcon type="minus" size="s" className="text-[#69707D] mx-auto" />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Users Table Card */}
      <WuiPanel
        accentColor="#006BB4"
        title={
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold text-[#1A1C21]">Daftar Pengguna</span>
            <WuiBadge>{filteredUsers.length}</WuiBadge>
          </div>
        }
        right={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-56">
              <WuiIcon type="search" size="s" className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#69707D]" />
              <input
                type="text"
                placeholder="Cari username, nama, email..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full h-8 pl-8 pr-3 text-[12px] bg-white border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4]"
              />
            </div>

            <div className="inline-flex rounded-[4px] border border-[#D3DAE6] bg-[#F5F7FA] p-0.5 text-[11px]">
              {(['all', 'admin', 'analyst', 'viewer'] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setRoleFilter(r)}
                  className={`px-2.5 py-1 rounded-[2px] capitalize font-medium transition-colors cursor-pointer ${
                    roleFilter === r
                      ? 'bg-white text-[#006BB4] font-semibold border border-[#D3DAE6]'
                      : 'text-[#535966] hover:text-[#1A1C21]'
                  }`}
                >
                  {r === 'all' ? 'Semua' : r}
                </button>
              ))}
            </div>
          </div>
        }
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-[#D3DAE6] text-[#535966] font-semibold text-[12px]">
                <th className="py-2.5 px-4">Username</th>
                <th className="py-2.5 px-4">Nama Lengkap</th>
                <th className="py-2.5 px-4">Email (Cloudflare Access)</th>
                <th className="py-2.5 px-4">Role</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Terakhir Login</th>
                <th className="py-2.5 px-4">Dibuat Pada</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E9EDF3]">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#535966]">
                    <div className="flex items-center justify-center gap-2">
                      <WuiIcon type="refresh" size="m" className="animate-spin text-[#006BB4]" />
                      <span>Memuat data pengguna...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#69707D]">
                    Tidak ada pengguna yang cocok dengan kriteria pencarian.
                  </td>
                </tr>
              ) : (
                filteredUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-[#FAFBFD] transition-colors">
                    <td className="py-2.5 px-4 font-mono font-semibold text-[#1A1C21]">
                      {u.username}
                    </td>
                    <td className="py-2.5 px-4 text-[#1A1C21] font-medium">{u.name || '-'}</td>
                    <td className="py-2.5 px-4 text-[#535966] font-mono text-[11px]">{u.email || '-'}</td>
                    <td className="py-2.5 px-4 font-mono text-[11px] font-semibold text-[#1A1C21] uppercase">
                      {u.role}
                    </td>
                    <td className="py-2.5 px-4 text-[12px] font-medium text-[#1A1C21]">
                      {u.active ? 'Aktif' : 'Nonaktif'}
                    </td>
                    <td className="py-2.5 px-4 text-[#535966] font-mono tabular-nums text-[11px]">
                      {u.last_login_at ? formatWazuhTime(u.last_login_at) : 'Belum pernah'}
                    </td>
                    <td className="py-2.5 px-4 text-[#535966] font-mono tabular-nums text-[11px]">
                      {formatWazuhTime(u.created_at)}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          type="button"
                          onClick={() => openEditModal(u)}
                          className="p-1.5 rounded-[4px] text-[#535966] hover:text-[#006BB4] hover:bg-[#EBF5FB] transition-colors cursor-pointer"
                          title="Edit Pengguna"
                        >
                          <WuiIcon type="pencil" size="s" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDelete(u)}
                          className="p-1.5 rounded-[4px] text-[#535966] hover:text-[#BD271E] hover:bg-[#FBECEB] transition-colors cursor-pointer"
                          title="Hapus Pengguna"
                        >
                          <WuiIcon type="trash" size="s" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </WuiPanel>

      {/* Modal Tambah Pengguna */}
      {isCreateOpen && (
        <WuiModal
          title={
            <>
              <WuiIcon type="user" size="m" className="text-[#006BB4]" />
              <span>Tambah Pengguna Baru</span>
            </>
          }
          onClose={() => setIsCreateOpen(false)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setIsCreateOpen(false)}
                className="px-3 py-1.5 border border-[#D3DAE6] rounded-[4px] text-[12px] text-[#535966] hover:bg-[#FAFBFD] cursor-pointer"
              >
                Batal
              </button>
              <button
                type="submit"
                form="create-user-form"
                disabled={isSubmitting}
                className="px-4 py-1.5 bg-[#006BB4] hover:bg-[#00538C] text-white rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {isSubmitting ? (
                  <WuiIcon type="refresh" size="s" className="animate-spin" />
                ) : (
                  <WuiIcon type="check" size="s" />
                )}
                <span>Simpan Pengguna</span>
              </button>
            </>
          }
        >
          <form id="create-user-form" onSubmit={handleCreateSubmit} className="space-y-3.5 text-[12.5px]">
            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">
                Email Cloudflare Access <span className="text-[#BD271E]">*</span>
              </label>
              <input
                type="email"
                required
                placeholder="user@domain.com"
                value={formEmail}
                onChange={(e) => setFormEmail(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
              />
              <span className="text-[11px] text-[#69707D]">
                Wajib sesuai dengan email yang digunakan login di Cloudflare Access SSO.
              </span>
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">
                Username <span className="text-[#BD271E]">*</span>
              </label>
              <input
                type="text"
                required
                pattern="^[a-zA-Z0-9_.-]{3,32}$"
                placeholder="username"
                value={formUsername}
                onChange={(e) => setFormUsername(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
              />
              <span className="text-[11px] text-[#69707D]">3-32 karakter alfanumerik.</span>
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">Nama Lengkap</label>
              <input
                type="text"
                placeholder="Nama Lengkap"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
              />
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">
                Password <span className="text-[#BD271E]">*</span>
              </label>
              <input
                type="password"
                required
                minLength={8}
                placeholder="Minimal 8 karakter"
                value={formPassword}
                onChange={(e) => setFormPassword(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
              />
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">
                Peran / Role Otorisasi <span className="text-[#BD271E]">*</span>
              </label>
              <select
                value={formRole}
                onChange={(e) => setFormRole(e.target.value as 'admin' | 'analyst' | 'viewer')}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] bg-white text-[12px]"
              >
                <option value="viewer">Viewer (Pemantauan Read-Only &amp; Audit)</option>
                <option value="analyst">Analyst (Triage Insiden &amp; Active Response)</option>
                <option value="admin">Admin (Akses Penuh, User Management &amp; API Keys)</option>
              </select>
            </div>
          </form>
        </WuiModal>
      )}

      {/* Modal Edit Pengguna */}
      {isEditOpen && selectedUser && (
        <WuiModal
          title={
            <>
              <WuiIcon type="pencil" size="m" className="text-[#006BB4]" />
              <span>Edit Pengguna: {selectedUser.username}</span>
            </>
          }
          onClose={() => setIsEditOpen(false)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setIsEditOpen(false)}
                className="px-3 py-1.5 border border-[#D3DAE6] rounded-[4px] text-[12px] text-[#535966] hover:bg-[#FAFBFD] cursor-pointer"
              >
                Batal
              </button>
              <button
                type="submit"
                form="edit-user-form"
                disabled={isSubmitting}
                className="px-4 py-1.5 bg-[#006BB4] hover:bg-[#00538C] text-white rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {isSubmitting ? (
                  <WuiIcon type="refresh" size="s" className="animate-spin" />
                ) : (
                  <WuiIcon type="check" size="s" />
                )}
                <span>Simpan Perubahan</span>
              </button>
            </>
          }
        >
          <form id="edit-user-form" onSubmit={handleEditSubmit} className="space-y-3.5 text-[12.5px]">
            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">Nama Lengkap</label>
              <input
                type="text"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
              />
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">Email Cloudflare Access</label>
              <input
                type="email"
                value={formEmail}
                onChange={(e) => setFormEmail(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
              />
              <span className="text-[11px] text-[#69707D]">
                Email yang terasosiasi dengan otorisasi login Cloudflare Access SSO.
              </span>
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">Peran / Role Otorisasi</label>
              <select
                value={formRole}
                onChange={(e) => setFormRole(e.target.value as 'admin' | 'analyst' | 'viewer')}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] bg-white text-[12px]"
              >
                <option value="viewer">Viewer (Read-Only &amp; Audit)</option>
                <option value="analyst">Analyst (Triage &amp; Active Response)</option>
                <option value="admin">Admin (Akses Penuh)</option>
              </select>
            </div>

            <div>
              <label className="block text-[#1A1C21] font-medium mb-1">
                Ganti Password (Kosongkan jika tidak ingin diubah)
              </label>
              <input
                type="password"
                minLength={8}
                placeholder="Password baru (opsional)"
                value={formPassword}
                onChange={(e) => setFormPassword(e.target.value)}
                className="w-full h-8 px-3 border border-[#D3DAE6] rounded-[4px] outline-none focus:border-[#006BB4] text-[12px]"
              />
            </div>

            <div className="flex items-center gap-2 pt-1">
              <input
                type="checkbox"
                id="activeCheck"
                checked={formActive}
                onChange={(e) => setFormActive(e.target.checked)}
                className="rounded-[2px] text-[#006BB4] focus:ring-0"
              />
              <label htmlFor="activeCheck" className="text-[#1A1C21] font-medium cursor-pointer">
                Status Akun Aktif (Dapat Login)
              </label>
            </div>
          </form>
        </WuiModal>
      )}

      {/* Delete User Confirmation Modal */}
      {deleteTarget && (
        <WuiModal
          title={
            <>
              <WuiIcon type="trash" size="m" className="text-[#BD271E]" />
              <span>Hapus Pengguna SOC</span>
            </>
          }
          onClose={() => setDeleteTarget(null)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                className="px-3 py-1.5 border border-[#D3DAE6] rounded-[4px] text-[12px] font-medium text-[#535966] hover:bg-[#FAFBFD] transition cursor-pointer"
              >
                Batal
              </button>
              <button
                type="button"
                onClick={executeDelete}
                disabled={isDeleting}
                className="px-3 py-1.5 rounded-[4px] text-[12px] font-semibold text-white bg-[#BD271E] hover:bg-[#9E1F18] transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {isDeleting ? <WuiIcon type="refresh" size="s" className="animate-spin" /> : null}
                <span>Hapus Pengguna</span>
              </button>
            </>
          }
        >
          <div className="space-y-3">
            <p className="text-[12px] text-[#535966] leading-relaxed">
              Apakah Anda yakin ingin menghapus akun pengguna{' '}
              <strong className="text-[#1A1C21]">{deleteTarget.username}</strong> ({deleteTarget.name})? Tindakan ini tidak dapat dibatalkan.
            </p>
            <div className="p-2.5 rounded-[4px] bg-[#FAFBFD] border border-[#D3DAE6] text-[11px] font-mono space-y-1">
              <div><span className="text-[#69707D]">Peran (Role):</span> {deleteTarget.role}</div>
              <div><span className="text-[#69707D]">Email:</span> {deleteTarget.email || '-'}</div>
              <div><span className="text-[#69707D]">User ID:</span> {deleteTarget.id}</div>
            </div>
          </div>
        </WuiModal>
      )}
    </div>
  );
}
