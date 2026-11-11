'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  UserPlus,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Eye,
  Trash2,
  Edit2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  User,
  Search,
  Check,
} from 'lucide-react';
import { formatWazuhTime } from '@/lib/fleet';

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

export function UserManagementView() {
  const [users, setUsers] = useState<UserItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | 'admin' | 'analyst' | 'viewer'>('all');

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
      showSuccess(`Pengguna '${formUsername}' dengan role '${formRole}' berhasil ditambahkan.`);
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
      showSuccess(`Pengguna '${selectedUser.username}' berhasil diperbarui.`);
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
      showSuccess(`Pengguna '${deleteTarget.username}' berhasil dihapus.`);
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
    <div className="space-y-6">
      {/* Top Banner / Heading */}
      <div className="bg-white border border-[#D3DAE6] rounded p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-[#E8F3FA] rounded-md text-[#006BB4]">
                <Users className="w-5 h-5" />
              </div>
              <h2 className="text-xl font-bold text-[#1A1C21]">
                User Management &amp; Role-Based Access Control (RBAC)
              </h2>
            </div>
            <p className="text-[13px] text-[#5A626F] mt-1.5 max-w-3xl leading-relaxed">
              Pusat kendali hak otorisasi berjenjang untuk personel SOC. Terintegrasi langsung dengan 
              autentikasi Cloudflare Access Zero Trust berbasis email. Tentukan hak akses Admin (penuh),
              Analyst (respons mitigasi insiden), dan Viewer (audit kepatuhan &amp; monitoring read-only).
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchUsers()}
              className="h-9 px-3 border border-[#D3DAE6] hover:bg-[#F5F7FA] text-[#1A1C21] rounded text-[13px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Refresh Data"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
            <button
              onClick={() => {
                resetForm();
                setIsCreateOpen(true);
              }}
              className="h-9 px-4 bg-[#006BB4] hover:bg-[#005593] text-white rounded text-[13px] font-medium flex items-center gap-2 shadow-sm transition-colors cursor-pointer"
            >
              <UserPlus className="w-4 h-4" />
              <span>Tambah Pengguna</span>
            </button>
          </div>
        </div>

        {/* Cloudflare Access Integration Info */}
        <div className="mt-4 p-3.5 bg-[#F0F6FA] border border-[#CBE0F0] rounded flex items-start gap-3 text-[12px] text-[#004A80]">
          <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0 text-[#006BB4]" />
          <div>
            <span className="font-semibold text-[#1A1C21]">Terintegrasi Cloudflare Access Zero Trust: </span>
            <span>
              Otorisasi sesi dashboard otomatis memetakan email login pengguna (dari header <code>cf-access-authenticated-user-email</code>)
              ke peran yang terdaftar di sistem ini. Misalnya <code>raviarnankeren@gmail.com</code> sebagai Admin dan <code>ravinewgemini@gmail.com</code> sebagai Viewer.
            </span>
          </div>
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

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white border border-[#D3DAE6] rounded p-4">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#5A626F]">
            Total Pengguna
          </div>
          <div className="text-2xl font-bold text-[#1A1C21] mt-1">{users.length}</div>
          <div className="text-[11px] text-[#8A94A6] mt-1">Akun personel terdaftar</div>
        </div>

        <div className="bg-white border border-[#D3DAE6] rounded p-4 border-l-4 border-l-[#BD271E]">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#5A626F]">
              Administrators
            </span>
            <ShieldAlert className="w-4 h-4 text-[#BD271E]" />
          </div>
          <div className="text-2xl font-bold text-[#BD271E] mt-1">{adminCount}</div>
          <div className="text-[11px] text-[#8A94A6] mt-1">Hak akses penuh &amp; API keys</div>
        </div>

        <div className="bg-white border border-[#D3DAE6] rounded p-4 border-l-4 border-l-[#006BB4]">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#5A626F]">
              Security Analysts
            </span>
            <Shield className="w-4 h-4 text-[#006BB4]" />
          </div>
          <div className="text-2xl font-bold text-[#006BB4] mt-1">{analystCount}</div>
          <div className="text-[11px] text-[#8A94A6] mt-1">Mitigasi &amp; respons ancaman</div>
        </div>

        <div className="bg-white border border-[#D3DAE6] rounded p-4 border-l-4 border-l-[#00A389]">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#5A626F]">
              Auditors &amp; Viewers
            </span>
            <Eye className="w-4 h-4 text-[#00A389]" />
          </div>
          <div className="text-2xl font-bold text-[#00A389] mt-1">{viewerCount}</div>
          <div className="text-[11px] text-[#8A94A6] mt-1">Monitoring read-only</div>
        </div>
      </div>

      {/* Role Permission Matrix Card */}
      <div className="bg-white border border-[#D3DAE6] rounded p-5">
        <h3 className="text-[14px] font-bold text-[#1A1C21] flex items-center gap-2 mb-3">
          <ShieldCheck className="w-4 h-4 text-[#006BB4]" />
          <span>Matriks Izin Role-Based Access Control (RBAC)</span>
        </h3>
        <div className="overflow-x-auto border border-[#EBEFF5] rounded">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F]">
                <th className="py-2.5 px-3 font-semibold">Kapabilitas &amp; Hak Operasi</th>
                <th className="py-2.5 px-3 font-semibold text-center w-28">Admin</th>
                <th className="py-2.5 px-3 font-semibold text-center w-28">Analyst</th>
                <th className="py-2.5 px-3 font-semibold text-center w-28">Viewer</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEFF5]">
              <tr>
                <td className="py-2 px-3 text-[#1A1C21] font-medium">
                  Monitoring Dashboard, Security Events, Network Map &amp; FIM
                </td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-[#1A1C21] font-medium">
                  Lihat Detail Telemetri Agent &amp; Hasil Sintesis Threat Intel
                </td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-[#1A1C21] font-medium">
                  Eksekusi Active Response (Karantina File &amp; Sinkhole Domain)
                </td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#BD271E] font-medium">Ditolak (403)</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-[#1A1C21] font-medium">
                  Jalankan On-Demand FIM Scan pada Endpoint
                </td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#BD271E] font-medium">Ditolak (403)</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-[#1A1C21] font-medium">
                  Manajemen API Keys Mesin (Penerbitan &amp; Pencabutan Token)
                </td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#BD271E] font-medium">Ditolak (403)</td>
                <td className="py-2 px-3 text-center text-[#BD271E] font-medium">Ditolak (403)</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-[#1A1C21] font-medium">
                  Manajemen Pengguna (User Management, Tambah/Edit Role, Reset Sandi)
                </td>
                <td className="py-2 px-3 text-center text-[#00A389] font-bold">Dizinkan</td>
                <td className="py-2 px-3 text-center text-[#BD271E] font-medium">Ditolak (403)</td>
                <td className="py-2 px-3 text-center text-[#BD271E] font-medium">Ditolak (403)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Users Table Card */}
      <div className="bg-white border border-[#D3DAE6] rounded p-5">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <h3 className="text-[14px] font-bold text-[#1A1C21]">Daftar Pengguna ({filteredUsers.length})</h3>
          </div>

          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
            {/* Search Input */}
            <div className="relative flex-1 md:w-64">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#8A94A6]" />
              <input
                type="text"
                placeholder="Cari username, nama, email..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-[12px] border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
              />
            </div>

            {/* Role Filter Tabs */}
            <div className="flex rounded border border-[#D3DAE6] overflow-hidden text-[11px] font-medium">
              {(['all', 'admin', 'analyst', 'viewer'] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setRoleFilter(r)}
                  className={`px-3 py-1.5 capitalize transition-colors ${
                    roleFilter === r
                      ? 'bg-[#006BB4] text-white'
                      : 'bg-white text-[#5A626F] hover:bg-[#F5F7FA]'
                  }`}
                >
                  {r === 'all' ? 'Semua' : r}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto border border-[#EBEFF5] rounded">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#D3DAE6] text-[#5A626F] font-semibold">
                <th className="py-2.5 px-3">Username</th>
                <th className="py-2.5 px-3">Nama Lengkap</th>
                <th className="py-2.5 px-3">Email (Cloudflare Access)</th>
                <th className="py-2.5 px-3">Role</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Terakhir Login</th>
                <th className="py-2.5 px-3">Dibuat Pada</th>
                <th className="py-2.5 px-3 text-right">Aksi</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEFF5]">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#5A626F]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#006BB4]" />
                      <span>Memuat data pengguna...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#8A94A6]">
                    Tidak ada pengguna yang cocok dengan kriteria pencarian.
                  </td>
                </tr>
              ) : (
                filteredUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-[#F8FAFC] transition-colors">
                    <td className="py-2.5 px-3 font-semibold text-[#1A1C21] flex items-center gap-2">
                      <User className="w-3.5 h-3.5 text-[#8A94A6]" />
                      <span>{u.username}</span>
                    </td>
                    <td className="py-2.5 px-3 text-[#1A1C21] font-medium">{u.name || '-'}</td>
                    <td className="py-2.5 px-3 text-[#5A626F]">{u.email || '-'}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                          u.role === 'admin'
                            ? 'bg-[#FDE8E8] text-[#BD271E]'
                            : u.role === 'analyst'
                            ? 'bg-[#EBF5FB] text-[#006BB4]'
                            : 'bg-[#E6F6F4] text-[#00A389]'
                        }`}
                      >
                        {u.role === 'admin' && <ShieldAlert className="w-3 h-3" />}
                        {u.role === 'analyst' && <Shield className="w-3 h-3" />}
                        {u.role === 'viewer' && <Eye className="w-3 h-3" />}
                        <span>{u.role}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium ${
                          u.active
                            ? 'bg-[#E6F6F4] text-[#00A389]'
                            : 'bg-[#F5F7FA] text-[#8A94A6]'
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            u.active ? 'bg-[#00A389]' : 'bg-[#8A94A6]'
                          }`}
                        />
                        <span>{u.active ? 'Aktif' : 'Nonaktif'}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-[#5A626F] font-mono text-[11px]">
                      {u.last_login_at ? formatWazuhTime(u.last_login_at) : 'Belum pernah'}
                    </td>
                    <td className="py-2.5 px-3 text-[#5A626F] font-mono text-[11px]">
                      {formatWazuhTime(u.created_at)}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openEditModal(u)}
                          className="p-1 rounded text-[#5A626F] hover:text-[#006BB4] hover:bg-[#EBF5FB] transition-colors"
                          title="Edit Pengguna &amp; Role"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleDelete(u)}
                          className="p-1 rounded text-[#5A626F] hover:text-[#BD271E] hover:bg-[#FDF3F2] transition-colors"
                          title="Hapus Pengguna"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal Tambah Pengguna */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
          <div className="bg-white rounded border border-[#D3DAE6] shadow-2xl max-w-md w-full p-6 animate-in fade-in duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-[#E1E6EB]">
              <h3 className="text-base font-bold text-[#1A1C21] flex items-center gap-2">
                <UserPlus className="w-4 h-4 text-[#006BB4]" />
                <span>Tambah Pengguna Baru</span>
              </h3>
              <button
                onClick={() => setIsCreateOpen(false)}
                className="p-1 rounded text-[#5A626F] hover:bg-[#F5F7FA]"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="mt-4 space-y-4 text-[13px]">
              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">
                  Email Cloudflare Access <span className="text-[#BD271E]">*</span>
                </label>
                <input
                  type="email"
                  required
                  placeholder="misal: ravinewgemini@gmail.com"
                  value={formEmail}
                  onChange={(e) => setFormEmail(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                />
                <span className="text-[11px] text-[#8A94A6]">
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
                  placeholder="misal: analyst_budi"
                  value={formUsername}
                  onChange={(e) => setFormUsername(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                />
                <span className="text-[11px] text-[#8A94A6]">3-32 karakter alfanumerik.</span>
              </div>

              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">Nama Lengkap</label>
                <input
                  type="text"
                  placeholder="misal: Budi Santoso"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
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
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                />
              </div>

              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">
                  Peran / Role Otorisasi <span className="text-[#BD271E]">*</span>
                </label>
                <select
                  value={formRole}
                  onChange={(e) => setFormRole(e.target.value as 'admin' | 'analyst' | 'viewer')}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] bg-white"
                >
                  <option value="viewer">Viewer (Pemantauan Read-Only &amp; Audit)</option>
                  <option value="analyst">Analyst (Triage Insiden &amp; Active Response)</option>
                  <option value="admin">Admin (Akses Penuh, User Management &amp; API Keys)</option>
                </select>
              </div>

              <div className="pt-3 border-t border-[#E1E6EB] flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-3 py-1.5 border border-[#D3DAE6] rounded text-[#5A626F] hover:bg-[#F5F7FA]"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-1.5 bg-[#006BB4] hover:bg-[#005593] text-white rounded font-medium flex items-center gap-1.5"
                >
                  {isSubmitting ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Check className="w-3.5 h-3.5" />
                  )}
                  <span>Simpan Pengguna</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal Edit Pengguna */}
      {isEditOpen && selectedUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
          <div className="bg-white rounded border border-[#D3DAE6] shadow-2xl max-w-md w-full p-6 animate-in fade-in duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-[#E1E6EB]">
              <h3 className="text-base font-bold text-[#1A1C21] flex items-center gap-2">
                <Edit2 className="w-4 h-4 text-[#006BB4]" />
                <span>Edit Pengguna: {selectedUser.username}</span>
              </h3>
              <button
                onClick={() => setIsEditOpen(false)}
                className="p-1 rounded text-[#5A626F] hover:bg-[#F5F7FA]"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleEditSubmit} className="mt-4 space-y-4 text-[13px]">
              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">Nama Lengkap</label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                />
              </div>

              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">Email Cloudflare Access</label>
                <input
                  type="email"
                  value={formEmail}
                  onChange={(e) => setFormEmail(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                />
                <span className="text-[11px] text-[#8A94A6]">
                  Email yang terasosiasi dengan otorisasi login Cloudflare Access SSO.
                </span>
              </div>

              <div>
                <label className="block text-[#1A1C21] font-medium mb-1">Peran / Role Otorisasi</label>
                <select
                  value={formRole}
                  onChange={(e) => setFormRole(e.target.value as 'admin' | 'analyst' | 'viewer')}
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] bg-white"
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
                  className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="activeCheck"
                  checked={formActive}
                  onChange={(e) => setFormActive(e.target.checked)}
                  className="rounded text-[#006BB4] focus:ring-0"
                />
                <label htmlFor="activeCheck" className="text-[#1A1C21] font-medium cursor-pointer">
                  Status Akun Aktif (Dapat Login)
                </label>
              </div>

              <div className="pt-3 border-t border-[#E1E6EB] flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsEditOpen(false)}
                  className="px-3 py-1.5 border border-[#D3DAE6] rounded text-[#5A626F] hover:bg-[#F5F7FA]"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-1.5 bg-[#006BB4] hover:bg-[#005593] text-white rounded font-medium flex items-center gap-1.5"
                >
                  {isSubmitting ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Check className="w-3.5 h-3.5" />
                  )}
                  <span>Simpan Perubahan</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete User Confirmation Modal */}
      {deleteTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="bg-white border border-[#D3DAE6] rounded w-full max-w-md p-5 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-full bg-[#FDF3F2] text-[#BD271E] shrink-0">
                <Trash2 className="w-5 h-5" />
              </div>
              <div className="flex-1">
                <h3 className="text-[14px] font-bold text-[#1A1C21]">
                  Hapus Pengguna SOC
                </h3>
                <p className="text-[12px] text-[#5A626F] mt-1 leading-relaxed">
                  Apakah Anda yakin ingin menghapus akun pengguna{' '}
                  <strong className="text-[#1A1C21]">{deleteTarget.username}</strong> ({deleteTarget.name})? Tindakan ini tidak dapat dibatalkan.
                </p>

                <div className="mt-3 p-2.5 rounded bg-[#F8FAFC] border border-[#E2E8F0] text-[11px] font-mono space-y-1">
                  <div><span className="text-[#8A94A6]">Peran (Role):</span> {deleteTarget.role}</div>
                  <div><span className="text-[#8A94A6]">Email:</span> {deleteTarget.email || '-'}</div>
                  <div><span className="text-[#8A94A6]">User ID:</span> {deleteTarget.id}</div>
                </div>

                <div className="flex items-center justify-end gap-2.5 mt-5">
                  <button
                    type="button"
                    onClick={() => setDeleteTarget(null)}
                    className="px-3 py-1.5 border border-[#D3DAE6] rounded text-[12px] font-medium text-[#5A626F] hover:bg-[#F5F7FA] transition"
                  >
                    Batal
                  </button>
                  <button
                    type="button"
                    onClick={executeDelete}
                    disabled={isDeleting}
                    className="px-3 py-1.5 rounded text-[12px] font-semibold text-white bg-[#BD271E] hover:bg-[#9E1F18] transition flex items-center gap-1.5"
                  >
                    {isDeleting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
                    <span>Hapus Pengguna</span>
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
