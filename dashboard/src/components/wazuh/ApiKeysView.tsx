'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Key,
  Plus,
  Copy,
  Check,
  Shield,
  Trash2,
  AlertTriangle,
  Code2,
  RefreshCw,
  Clock,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Mail,
  Send,
  ShieldCheck,
} from 'lucide-react';
import { formatWazuhTime } from '@/lib/fleet';

interface ApiKeyItem {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
  revoked: boolean;
}

interface CreatedKeyResponse {
  id: string;
  name: string;
  token: string;
  prefix: string;
  scopes: string[];
  created_at: string;
}

/**
 * Komponen Cuplikan Kode bergaya bersih (Clean Light Box).
 * Terinspirasi dari panduan lab/cloud console:
 * Background terang, border lembut, teks hijau monospace, tombol salin di kanan.
 */
function SnippetBox({
  label,
  code,
  helperText,
}: {
  label: string;
  code: string;
  helperText?: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (!navigator?.clipboard) return;
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="space-y-1.5">
      <div className="text-[12px] text-[#1A1C21] font-medium">{label}</div>
      <div className="bg-white border border-[#D3DAE6] rounded-md px-4 py-2.5 flex items-center justify-between gap-3 shadow-2xs hover:border-[#B5C2D4] transition">
        <code className="font-mono text-[12px] text-[#15803D] select-all break-all leading-relaxed">
          {code}
        </code>
        <button
          onClick={handleCopy}
          className="p-1.5 rounded text-[#5A626F] hover:text-[#1A1C21] hover:bg-[#F0F4F8] transition shrink-0"
          title="Salin cuplikan"
        >
          {copied ? (
            <Check className="w-4 h-4 text-[#15803D]" />
          ) : (
            <Copy className="w-4 h-4" />
          )}
        </button>
      </div>
      {helperText && (
        <div className="text-[11px] text-[#5A626F]">{helperText}</div>
      )}
    </div>
  );
}

export function ApiKeysView() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isAuthRequired, setIsAuthRequired] = useState(false);
  const [loginInput, setLoginInput] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // State 2FA (Email & Telegram)
  const [otpInput, setOtpInput] = useState('');
  const [maskedEmail, setMaskedEmail] = useState('r****n@gmail.com');
  const [isRequestingOtp, setIsRequestingOtp] = useState(false);
  const [isVerifyingOtp, setIsVerifyingOtp] = useState(false);
  const [otpCooldown, setOtpCooldown] = useState(0);
  const [otpMessage, setOtpMessage] = useState<string | null>(null);
  const [otpError, setOtpError] = useState<string | null>(null);
  const [showManualToken, setShowManualToken] = useState(false);

  // Timer cooldown 2FA
  useEffect(() => {
    if (otpCooldown <= 0) return;
    const timer = setInterval(() => {
      setOtpCooldown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [otpCooldown]);

  // State panduan integrasi (default tertutup agar UI utama tetap bersih)
  const [isGuideOpen, setIsGuideOpen] = useState(false);

  // State pembuatan key baru
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [selectedScopes, setSelectedScopes] = useState<string[]>([
    'read:fleet',
    'read:intel',
  ]);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // State one-time reveal
  const [revealedKey, setRevealedKey] = useState<CreatedKeyResponse | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);

  // State revoke
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const loadKeys = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch('/api/keys');
      if (res.status === 401) {
        setIsAuthRequired(true);
        setLoading(false);
        return;
      }
      setIsAuthRequired(false);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        setError(errData.error || `HTTP ${res.status}`);
        return;
      }
      const data = await res.json();
      setKeys(data.keys || []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`Gagal memuat API Keys: ${msg}`);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleRefresh = () => {
    setLoading(true);
    loadKeys();
  };

  const handleRequestOtp = async () => {
    try {
      setIsRequestingOtp(true);
      setOtpError(null);
      setOtpMessage(null);
      const res = await fetch('/api/auth/2fa/request', { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setOtpError(data.error || 'Gagal mengirim kode verifikasi 2FA.');
        return;
      }
      if (data.maskedEmail) setMaskedEmail(data.maskedEmail);
      setOtpCooldown(data.cooldownSeconds || 30);
      setOtpMessage(data.message || 'Kode verifikasi telah dikirim.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setOtpError(`Koneksi gagal: ${msg}`);
    } finally {
      setIsRequestingOtp(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otpInput.trim()) return;

    try {
      setIsVerifyingOtp(true);
      setOtpError(null);
      const res = await fetch('/api/auth/2fa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: otpInput.trim() }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setOtpError(data.error || 'Kode verifikasi salah.');
        return;
      }

      setOtpInput('');
      setOtpMessage(null);
      setIsAuthRequired(false);
      setLoading(true);
      loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setOtpError(`Verifikasi gagal: ${msg}`);
    } finally {
      setIsVerifyingOtp(false);
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginInput.trim()) return;

    try {
      setIsLoggingIn(true);
      const res = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: loginInput.trim() }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Token tidak valid');
        return;
      }

      setLoginInput('');
      setIsAuthRequired(false);
      setLoading(true);
      loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      alert(`Login gagal: ${msg}`);
    } finally {
      setIsLoggingIn(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    fetch('/api/keys')
      .then(async (res) => {
        if (res.status === 401) {
          if (!cancelled) {
            setIsAuthRequired(true);
            setLoading(false);
          }
          return null;
        }
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.error || `HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        if (!cancelled && data) {
          setKeys(data.keys || []);
          setIsAuthRequired(false);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(String(err.message || err));
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleToggleScope = (scope: string) => {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    );
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyName.trim()) return;

    try {
      setIsSubmitting(true);
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: keyName.trim(),
          scopes: selectedScopes,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Gagal membuat API Key');
        return;
      }

      const created: CreatedKeyResponse = await res.json();
      setRevealedKey(created);
      setIsCreateModalOpen(false);
      setKeyName('');
      setSelectedScopes(['read:fleet', 'read:intel']);
      loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      alert(`Error membuat API Key: ${msg}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRevokeKey = async (id: string, name: string) => {
    if (
      !window.confirm(
        `Yakin ingin mencabut (revoke) API Key "${name}"? Tindakan ini tidak dapat dibatalkan.`
      )
    ) {
      return;
    }

    try {
      setRevokingId(id);
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'revoke', id }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Gagal mencabut API Key');
        return;
      }

      loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      alert(`Error saat revoke: ${msg}`);
    } finally {
      setRevokingId(null);
    }
  };

  const handleCopyModalToken = (text: string) => {
    if (!navigator?.clipboard) return;
    navigator.clipboard.writeText(text).then(() => {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    });
  };

  const activeKeysCount = keys.filter((k) => !k.revoked).length;

  return (
    <div className="space-y-4">
      {/* Header Utama */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-[16px] font-semibold text-[#1A1C21]">
            API Keys & Agent Access
          </h2>
          <p className="text-[12px] text-[#5A626F] mt-0.5">
            Kelola kunci akses machine-to-machine untuk Autonomous AI Agent (Gemini, DeepSeek, n8n) dan automasi mitigasi SOAR.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#1A1C21] bg-white border border-[#D3DAE6] rounded hover:bg-[#F8F9FB] transition disabled:opacity-50"
            title="Segarkan daftar API Key"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-white bg-[#006BB4] hover:bg-[#004B80] rounded shadow-xs transition"
          >
            <Plus className="w-4 h-4" />
            Generate New Key
          </button>
        </div>
      </div>

      {/* Ringkasan Status Keamanan */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="bg-white border border-[#D3DAE6] rounded p-3.5 flex items-center gap-3">
          <div className="p-2.5 rounded bg-[#E6F4EA] text-[#137333]">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-[#5A626F] font-medium uppercase tracking-wider">
              Kunci Aktif
            </div>
            <div className="text-[20px] font-bold text-[#1A1C21] leading-tight">
              {activeKeysCount}{' '}
              <span className="text-[12px] font-normal text-[#5A626F]">
                dari {keys.length} total
              </span>
            </div>
          </div>
        </div>

        <div className="bg-white border border-[#D3DAE6] rounded p-3.5 flex items-center gap-3">
          <div className="p-2.5 rounded bg-[#F0F4F8] text-[#006BB4]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-[#5A626F] font-medium uppercase tracking-wider">
              Enkripsi & Hashing
            </div>
            <div className="text-[13px] font-semibold text-[#1A1C21] leading-tight">
              SHA-256 One-Way Hash
            </div>
            <div className="text-[11px] text-[#5A626F] mt-0.5">
              Token mentah tidak disimpan di database
            </div>
          </div>
        </div>

        <div className="bg-white border border-[#D3DAE6] rounded p-3.5 flex items-center gap-3">
          <div className="p-2.5 rounded bg-[#FEF3E8] text-[#B25E09]">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-[#5A626F] font-medium uppercase tracking-wider">
              Audit Telemetri
            </div>
            <div className="text-[13px] font-semibold text-[#1A1C21] leading-tight">
              Akses Per-Agent Tercatat
            </div>
            <div className="text-[11px] text-[#5A626F] mt-0.5">
              Riwayat last_used otomatis ter-update
            </div>
          </div>
        </div>
      </div>

      {/* Kartu Autentikasi Dua Langkah (2FA) jika diperlukan login */}
      {isAuthRequired && (
        <div className="bg-white border border-[#B8D7ED] rounded-lg p-5 shadow-xs transition">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded-lg bg-[#EBF5FB] text-[#006BB4] mt-0.5 shrink-0">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <h3 className="text-[15px] font-semibold text-[#1A1C21]">
                  Verifikasi Keamanan Dua Langkah (2FA)
                </h3>
                <span className="px-2 py-0.5 text-[10px] font-medium bg-[#EBF5FB] text-[#006BB4] rounded-full border border-[#CCE3F5]">
                  Admin Gate
                </span>
              </div>
              <p className="text-[12px] text-[#5A626F] mt-1 max-w-xl leading-relaxed">
                Pengelolaan API Key dilindungi oleh verifikasi identitas administrator. Sistem akan mengirimkan kode OTP 6-digit ke email resmi administrator yang terdaftar.
              </p>

              {/* Status Pengiriman Email Administrator */}
              <div className="mt-3.5 p-3 rounded-md bg-[#F8FAFC] border border-[#E2E8F0] flex flex-wrap items-center justify-between gap-3 max-w-xl">
                <div className="flex items-center gap-2">
                  <Mail className="w-4 h-4 text-[#5A626F]" />
                  <span className="text-[12px] text-[#5A626F]">Email Terdaftar:</span>
                  <code className="text-[12px] font-mono font-medium text-[#1A1C21] bg-white px-2 py-0.5 rounded border border-[#D3DAE6]">
                    {maskedEmail}
                  </code>
                </div>

                <button
                  type="button"
                  onClick={handleRequestOtp}
                  disabled={isRequestingOtp || otpCooldown > 0}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-white bg-[#006BB4] hover:bg-[#004B80] rounded transition disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed shadow-2xs"
                >
                  <Send className="w-3.5 h-3.5" />
                  {isRequestingOtp
                    ? 'Mengirim...'
                    : otpCooldown > 0
                    ? `Kirim Ulang (${otpCooldown}s)`
                    : 'Kirim Kode Verifikasi'}
                </button>
              </div>

              {/* Pesan Feedback Pengiriman */}
              {otpMessage && (
                <div className="mt-2.5 p-2.5 rounded bg-[#F0FDF4] border border-[#BBF7D0] text-[#15803D] text-[12px] flex items-center gap-2 max-w-xl">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{otpMessage}</span>
                </div>
              )}

              {otpError && (
                <div className="mt-2.5 p-2.5 rounded bg-[#FEF2F2] border border-[#FECACA] text-[#DC2626] text-[12px] flex items-center gap-2 max-w-xl">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{otpError}</span>
                </div>
              )}

              {/* Form Input Kode Verifikasi OTP */}
              <form onSubmit={handleVerifyOtp} className="mt-4 flex items-center gap-2 max-w-md">
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  placeholder="000000"
                  value={otpInput}
                  onChange={(e) => setOtpInput(e.target.value.replace(/\D/g, ''))}
                  className="w-36 px-3 py-1.5 text-[15px] font-mono font-bold tracking-[6px] text-center bg-[#F8FAFC] border border-[#D3DAE6] rounded focus:outline-none focus:border-[#006BB4] focus:bg-white"
                />
                <button
                  type="submit"
                  disabled={isVerifyingOtp || otpInput.trim().length !== 6}
                  className="px-4 py-1.5 text-[12px] font-medium text-white bg-[#15803D] hover:bg-[#166534] rounded transition disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed shadow-2xs"
                >
                  {isVerifyingOtp ? 'Memverifikasi...' : 'Verifikasi & Buka Akses'}
                </button>
              </form>

              {/* Opsi Darurat Teknisi (Fallback Master Token) */}
              <div className="mt-4 pt-3 border-t border-[#EBF2F7] max-w-xl">
                <button
                  type="button"
                  onClick={() => setShowManualToken((prev) => !prev)}
                  className="text-[11px] text-[#5A626F] hover:text-[#1A1C21] underline cursor-pointer"
                >
                  {showManualToken
                    ? 'Sembunyikan opsi master token'
                    : 'Opsi Teknisi: Buka dengan Master Token (.env)'}
                </button>

                {showManualToken && (
                  <form onSubmit={handleLoginSubmit} className="mt-2.5 flex items-center gap-2 max-w-md">
                    <input
                      type="password"
                      placeholder="Masukkan DASHBOARD_LOGIN_TOKEN"
                      value={loginInput}
                      onChange={(e) => setLoginInput(e.target.value)}
                      className="flex-1 px-3 py-1 text-[11px] bg-[#F8FAFC] border border-[#D3DAE6] rounded focus:outline-none focus:border-[#006BB4]"
                    />
                    <button
                      type="submit"
                      disabled={isLoggingIn || !loginInput.trim()}
                      className="px-3 py-1 text-[11px] font-medium text-[#1A1C21] bg-[#E2E8F0] hover:bg-[#CBD5E1] rounded transition disabled:opacity-50"
                    >
                      {isLoggingIn ? 'Verifikasi...' : 'Login Token'}
                    </button>
                  </form>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Pesan Error umum jika ada */}
      {error && !isAuthRequired && (
        <div className="border border-[#F5C2C0] bg-[#FDF3F2] text-[#BD271E] text-[12px] rounded p-3 flex items-center gap-2">
          <XCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Tabel Daftar Kunci */}
      <div className="bg-white border border-[#D3DAE6] rounded overflow-hidden">
        <div className="px-4 py-3 border-b border-[#D3DAE6] flex items-center justify-between">
          <h3 className="text-[13px] font-semibold text-[#1A1C21]">Daftar API Access Keys</h3>
          <span className="text-[11px] text-[#5A626F]">{keys.length} kunci terdaftar</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-[#5A626F] text-[13px]">Memuat data API Keys...</div>
        ) : keys.length === 0 ? (
          <div className="p-8 text-center">
            <Key className="w-8 h-8 text-[#8A94A6] mx-auto mb-2" />
            <div className="text-[13px] font-semibold text-[#1A1C21]">Belum ada API Key</div>
            <p className="text-[12px] text-[#5A626F] mt-1 max-w-sm mx-auto">
              Klik tombol &quot;Generate New Key&quot; di kanan atas untuk membuat kunci akses pertama bagi AI Agent Anda.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wider text-[#8A94A6] border-b border-[#D3DAE6] bg-[#FAFBFD]">
                  <th className="px-4 py-2.5 font-semibold">Nama Token / Agent</th>
                  <th className="px-4 py-2.5 font-semibold">Identifier Prefix</th>
                  <th className="px-4 py-2.5 font-semibold">Cakupan Izin (Scopes)</th>
                  <th className="px-4 py-2.5 font-semibold">Dibuat Pada</th>
                  <th className="px-4 py-2.5 font-semibold">Terakhir Digunakan</th>
                  <th className="px-4 py-2.5 font-semibold">Status</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Aksi</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.id} className="border-b border-[#EDEEF2] last:border-0 hover:bg-[#F8FAFC]">
                    <td className="px-4 py-2.5 font-medium text-[#1A1C21]">
                      <div className="flex items-center gap-1.5">
                        <Key className="w-3.5 h-3.5 text-[#006BB4]" />
                        <span>{k.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-[#475569]">
                      <code>{k.prefix}</code>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1 flex-wrap">
                        {k.scopes.map((s) => (
                          <span
                            key={s}
                            className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-medium ${
                              s === 'write:actions'
                                ? 'bg-[#FEF3E8] text-[#B25E09] border border-[#FDE5CC]'
                                : s === 'read:intel'
                                  ? 'bg-[#F3E8FF] text-[#7E22CE] border border-[#E9D5FF]'
                                  : 'bg-[#E0F2FE] text-[#0369A1] border border-[#BAE6FD]'
                            }`}
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-[#5A626F]">{formatWazuhTime(k.created_at)}</td>
                    <td className="px-4 py-2.5 text-[#5A626F]">
                      {k.last_used_at ? formatWazuhTime(k.last_used_at) : '(Belum pernah)'}
                    </td>
                    <td className="px-4 py-2.5">
                      {k.revoked ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#8A94A6] bg-[#F1F5F9] px-2 py-0.5 rounded">
                          Revoked
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#137333] bg-[#E6F4EA] px-2 py-0.5 rounded">
                          Active
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      {!k.revoked && (
                        <button
                          onClick={() => handleRevokeKey(k.id, k.name)}
                          disabled={revokingId === k.id}
                          className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[#BD271E] hover:bg-[#FDECEA] rounded transition disabled:opacity-50"
                          title="Cabut akses token ini"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>{revokingId === k.id ? 'Memproses...' : 'Revoke'}</span>
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Panduan Cuplikan Kode Integrasi (Clean Light Box Style) */}
      <div className="bg-white border border-[#D3DAE6] rounded overflow-hidden">
        <button
          onClick={() => setIsGuideOpen(!isGuideOpen)}
          className="w-full px-4 py-3 bg-[#FAFBFD] hover:bg-[#F0F4F8] flex items-center justify-between text-left transition"
        >
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-[#006BB4]" />
            <span className="text-[13px] font-semibold text-[#1A1C21]">
              Panduan Integrasi AI Agent & Cuplikan Kode
            </span>
            <span className="text-[11px] text-[#5A626F] hidden sm:inline">
              (Format autentikasi header untuk script automasi atau agen otonom)
            </span>
          </div>
          <div className="flex items-center gap-1 text-[12px] text-[#006BB4] font-medium">
            <span>{isGuideOpen ? 'Sembunyikan' : 'Lihat Cuplikan'}</span>
            {isGuideOpen ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </div>
        </button>

        {isGuideOpen && (
          <div className="p-4 space-y-4 border-t border-[#EDEEF2] bg-[#FAFBFD] animate-in fade-in duration-150">
            <p className="text-[12px] text-[#5A626F]">
              Salin cuplikan kode di bawah ini untuk disematkan pada skrip automasi atau konfigurasi HTTP tool AI Agent Anda:
            </p>

            <SnippetBox
              label="1. Format Header HTTP Autentikasi (Bearer Token):"
              code="Authorization: Bearer soar_live_xxxxxxxxxxxxxxxxxxxxxxxx"
              helperText="Gunakan header ini di setiap panggilan API untuk mengidentifikasi agen."
            />

            <SnippetBox
              label="2. Cuplikan cURL Baca Riwayat Ancaman & IoC (Scope: read:intel):"
              code='curl -s -H "Authorization: Bearer <API_KEY>" https://soar.raviarnan.dev/api/events/history?limit=10'
              helperText="Mengembalikan ringkasan deteksi FIM, reputasi VirusTotal, dan analisis reasoning."
            />

            <SnippetBox
              label="3. Cuplikan cURL Eksekusi Karantina File (Scope: write:actions):"
              code='curl -s -X POST -H "Authorization: Bearer <API_KEY>" -H "Content-Type: application/json" -d "{\"agent_id\":\"003\",\"action\":\"quarantine\",\"target\":\"/tmp/malware.exe\"}" https://soar.raviarnan.dev/api/commands'
              helperText="Mengirimkan instruksi isolasi file langsung ke agen endpoint via Active Response."
            />
          </div>
        )}
      </div>

      {/* Modal Buat Key Baru */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-5 space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-[#EDEEF2] pb-3">
              <h3 className="text-[14px] font-semibold text-[#1A1C21] flex items-center gap-2">
                <Key className="w-4 h-4 text-[#006BB4]" />
                Generate New API Key
              </h3>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="text-[#8A94A6] hover:text-[#1A1C21] text-[18px] leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateKey} className="space-y-4">
              <div>
                <label className="block text-[12px] font-medium text-[#1A1C21] mb-1">
                  Nama Token / Agent
                </label>
                <input
                  type="text"
                  required
                  placeholder="Contoh: Gemini Triage Agent, Auto Containment Bot"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  className="w-full px-3 py-1.5 text-[12px] bg-[#F8FAFC] border border-[#D3DAE6] rounded focus:outline-none focus:border-[#006BB4]"
                />
              </div>

              <div>
                <label className="block text-[12px] font-medium text-[#1A1C21] mb-2">
                  Cakupan Izin (Scopes)
                </label>
                <div className="space-y-2 text-[12px]">
                  <label className="flex items-start gap-2 p-2 border border-[#EDEEF2] rounded hover:bg-[#F8FAFC] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedScopes.includes('read:fleet')}
                      onChange={() => handleToggleScope('read:fleet')}
                      className="mt-0.5 rounded"
                    />
                    <div>
                      <div className="font-semibold text-[#1A1C21]">read:fleet</div>
                      <div className="text-[11px] text-[#5A626F]">
                        Membaca status roster agen endpoint, metrik CPU/RAM, dan telemetri kesehatan.
                      </div>
                    </div>
                  </label>

                  <label className="flex items-start gap-2 p-2 border border-[#EDEEF2] rounded hover:bg-[#F8FAFC] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedScopes.includes('read:intel')}
                      onChange={() => handleToggleScope('read:intel')}
                      className="mt-0.5 rounded"
                    />
                    <div>
                      <div className="font-semibold text-[#1A1C21]">read:intel</div>
                      <div className="text-[11px] text-[#5A626F]">
                        Membaca riwayat deteksi ancaman, analisis reasoning AI, dan korelasi hash IoC.
                      </div>
                    </div>
                  </label>

                  <label className="flex items-start gap-2 p-2 border border-[#EDEEF2] rounded hover:bg-[#F8FAFC] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedScopes.includes('write:actions')}
                      onChange={() => handleToggleScope('write:actions')}
                      className="mt-0.5 rounded"
                    />
                    <div>
                      <div className="font-semibold text-[#BD271E]">write:actions</div>
                      <div className="text-[11px] text-[#5A626F]">
                        Mengeksekusi tindakan mitigasi aktif (Karantina file, isolasi sinkhole, scan).
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#EDEEF2]">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-3 py-1.5 text-[12px] font-medium text-[#5A626F] hover:bg-[#F0F4F8] rounded transition"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || selectedScopes.length === 0}
                  className="px-3 py-1.5 text-[12px] font-medium text-white bg-[#006BB4] hover:bg-[#004B80] rounded transition disabled:opacity-50"
                >
                  {isSubmitting ? 'Membuat...' : 'Buat API Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal One-Time Reveal (Clean Light Box Style persis referensi) */}
      {revealedKey && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-2xl max-w-lg w-full p-5 space-y-4 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center gap-2 text-[#137333]">
              <CheckCircle2 className="w-5 h-5" />
              <h3 className="text-[15px] font-semibold text-[#1A1C21]">API Key Berhasil Dibuat</h3>
            </div>

            <div className="border border-[#FDE5CC] bg-[#FEF3E8] p-3 rounded flex items-start gap-2.5 text-[12px] text-[#B25E09]">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                <strong>Penting:</strong> Salin API Key di bawah ini sekarang. Demi alasan keamanan, token rahasia ini tidak akan pernah ditampilkan lagi.
              </span>
            </div>

            <div className="space-y-1.5">
              <div className="text-[12px] font-medium text-[#1A1C21]">
                Token Akses untuk <strong>{revealedKey.name}</strong>:
              </div>
              <div className="bg-white border border-[#D3DAE6] rounded-md px-4 py-3 flex items-center justify-between gap-3 shadow-2xs hover:border-[#B5C2D4] transition">
                <code className="font-mono text-[13px] text-[#15803D] select-all break-all leading-relaxed">
                  {revealedKey.token}
                </code>
                <button
                  onClick={() => handleCopyModalToken(revealedKey.token)}
                  className="p-1.5 rounded text-[#5A626F] hover:text-[#1A1C21] hover:bg-[#F0F4F8] transition shrink-0"
                  title="Salin ke clipboard"
                >
                  {copiedToken ? (
                    <Check className="w-4 h-4 text-[#15803D]" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-[#EDEEF2]">
              <button
                onClick={() => setRevealedKey(null)}
                className="px-4 py-1.5 text-[12px] font-medium text-white bg-[#1A1C21] hover:bg-[#2C313A] rounded transition"
              >
                Selesai & Tutup
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
