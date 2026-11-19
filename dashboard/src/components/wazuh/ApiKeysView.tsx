'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import { formatWazuhTime } from '@/lib/fleet';
import {
  WuiBadge,
  WuiCallOut,
  WuiCodeBlock,
  WuiHealth,
  WuiModal,
  WuiPageHeader,
  WuiPanel,
} from '../wui/WuiPrimitives';

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
  rotated_from?: string;
}

const AI_AGENT_SETUP_PROMPT = `Kamu adalah AI Security Operations Agent yang terhubung ke SOAR Fleet Control Plane.

1. Konfigurasi Autentikasi & Endpoint:
   - Simpan API Key di environment variable / secret manager (contoh: SOAR_API_KEY), jangan pernah hardcode di kode sumber.
   - Base URL: gunakan SOAR_API_URL dari konfigurasi server Anda (contoh: https://soar.example.com).
   - Sertakan header di setiap HTTP request:
     Authorization: Bearer <SOAR_API_KEY>

2. Daftar Endpoint & Scope yang Tersedia:
   - [read:fleet]  GET /api/fleet
     Melihat status kesehatan fleet, daftar agent terdaftar, agent_id, OS, dan IP.
   - [read:intel]  GET /api/events/history?limit=20&severity=CRITICAL,HIGH
     Mengambil riwayat alert FIM/Wazuh, SHA-256 hash, dan analisis reasoning.
   - [write:investigations]  GET /api/investigations & POST /api/investigations
     Membaca & menyimpan laporan investigasi AI Agent (MCP) agar tampil terpisah di tab 'Investigasi AI Agent' pada halaman Threat Intelligence.
   - [write:actions] POST /api/commands (Content-Type: application/json)
     Body: {"agent_id":"<id>","action":"quarantine|sinkhole|unsinkhole|scan|restore","target":"<path_absolut_atau_domain>"}

3. Aturan Operasional & Keamanan:
   - Selalu lakukan GET /api/fleet dan GET /api/events/history lebih dulu untuk memverifikasi agent_id, severity, dan target sebelum menjalankan aksi.
   - Dilarang mengeksekusi quarantine pada event berkategori INFO atau berstatus Benign.
   - Validasi bahwa target quarantine/scan/restore adalah path absolut tanpa traversal, dan target sinkhole adalah domain valid.
   - Minta konfirmasi operator sebelum memanggil POST /api/commands, kecuali untuk eskalasi otomatis insiden CRITICAL yang sudah disetujui.`;

export function ApiKeysView() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isAuthRequired, setIsAuthRequired] = useState(false);
  const [loginInput, setLoginInput] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // State 2FA (Email & Telegram)
  const [otpInput, setOtpInput] = useState('');
  const [maskedEmail, setMaskedEmail] = useState('admin@example.com');
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

  // State revoke & rotate
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<{ id: string; name: string } | null>(null);
  const [rotatingId, setRotatingId] = useState<string | null>(null);
  const [rotateTarget, setRotateTarget] = useState<{ id: string; name: string } | null>(null);

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
        setOtpError(err.error || 'Token tidak valid');
        return;
      }

      setLoginInput('');
      setIsAuthRequired(false);
      setLoading(true);
      loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setOtpError(`Login gagal: ${msg}`);
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
        setError(err.error || 'Gagal membuat API Key');
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
      setError(`Error membuat API Key: ${msg}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRevokeKey = (id: string, name: string) => {
    setRevokeTarget({ id, name });
  };

  const executeRevokeKey = async () => {
    if (!revokeTarget) return;

    try {
      setRevokingId(revokeTarget.id);
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'revoke', id: revokeTarget.id }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setError(err.error || 'Gagal mencabut API Key');
        return;
      }

      setRevokeTarget(null);
      loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`Error saat revoke: ${msg}`);
    } finally {
      setRevokingId(null);
    }
  };

  const handleRotateKey = (id: string, name: string) => {
    setRotateTarget({ id, name });
  };

  const executeRotateKey = async () => {
    if (!rotateTarget) return;

    try {
      setRotatingId(rotateTarget.id);
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'rotate', id: rotateTarget.id }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setError(err.error || 'Gagal melakukan rotate API Key');
        return;
      }

      const rotated: CreatedKeyResponse = await res.json();
      setRotateTarget(null);
      setCopiedToken(false);
      setRevealedKey(rotated);
      loadKeys();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`Error saat rotate: ${msg}`);
    } finally {
      setRotatingId(null);
    }
  };

  const handleCopyModalToken = (text: string) => {
    if (!navigator?.clipboard) return;
    navigator.clipboard.writeText(text).then(() => {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    });
  };

  const visibleKeys = keys.filter((k) => !k.revoked);
  const activeKeysCount = visibleKeys.length;

  return (
    <div className="space-y-4">
      <WuiPageHeader
        title="API Keys &amp; Machine Access"
        description="Kelola kunci akses machine-to-machine untuk AI Agent dan automasi mitigasi SOAR."
        actions={
          <>
            <button
              type="button"
              onClick={handleRefresh}
              disabled={loading}
              className="h-8 px-3 text-[12px] font-medium text-[#1A1C21] bg-white border border-[#D3DAE6] rounded-[4px] hover:bg-[#FAFBFD] inline-flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
              title="Segarkan daftar API Key"
            >
              <WuiIcon type="refresh" size="s" className={loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
            <button
              type="button"
              onClick={() => setIsCreateModalOpen(true)}
              className="h-8 px-3 text-[12px] font-medium text-white bg-[#006BB4] hover:bg-[#00538C] rounded-[4px] inline-flex items-center gap-1.5 transition cursor-pointer"
            >
              <WuiIcon type="plus" size="s" />
              <span>Generate New Key</span>
            </button>
          </>
        }
      />

      {/* WUI Unified Summary Bar */}
      <div className="bg-white border border-[#D3DAE6] rounded-[4px] grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-[#E9EDF3]">
        <div className="px-4 py-3">
          <div className="text-[12px] font-medium text-[#535966]">
            Active Keys
          </div>
          <div className="text-[22px] font-semibold text-[#007871] font-mono tabular-nums mt-0.5 leading-tight">
            {activeKeysCount}{' '}
            <span className="text-[12px] font-sans font-normal text-[#535966]">
              aktif
            </span>
          </div>
        </div>

        <div className="px-4 py-3">
          <div className="text-[12px] font-medium text-[#535966]">
            Hashing Algorithm
          </div>
          <div className="text-[13px] font-semibold text-[#1A1C21] mt-1">
            SHA-256 One-Way Hash
          </div>
          <div className="text-[11px] text-[#69707D] mt-0.5">
            Token mentah tidak pernah disimpan di database
          </div>
        </div>

        <div className="px-4 py-3">
          <div className="text-[12px] font-medium text-[#535966]">
            Telemetry Audit
          </div>
          <div className="text-[13px] font-semibold text-[#1A1C21] mt-1">
            Per-Agent Scope &amp; Last Used
          </div>
          <div className="text-[11px] text-[#69707D] mt-0.5">
            Timestamp last_used otomatis tercatat
          </div>
        </div>
      </div>

      {/* Kartu Autentikasi Dua Langkah (2FA) */}
      {isAuthRequired && (
        <WuiPanel
          title="Verifikasi Keamanan Dua Langkah (2FA)"
          accentColor="#006BB4"
        >
          <div className="space-y-3.5 max-w-xl">
            <p className="text-[12px] text-[#535966] leading-relaxed">
              Pengelolaan API Key dilindungi verifikasi identitas administrator. Sistem akan mengirimkan kode OTP 6-digit ke email resmi administrator yang terdaftar.
            </p>

            <div className="p-3 rounded-[4px] bg-[#FAFBFD] border border-[#D3DAE6] flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <WuiIcon type="email" size="m" className="text-[#535966]" />
                <span className="text-[12px] text-[#535966]">Email Terdaftar:</span>
                <code className="text-[12px] font-mono font-medium text-[#1A1C21] bg-white px-2 py-0.5 rounded-[4px] border border-[#D3DAE6]">
                  {maskedEmail}
                </code>
              </div>

              <button
                type="button"
                onClick={handleRequestOtp}
                disabled={isRequestingOtp || otpCooldown > 0}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-white bg-[#006BB4] hover:bg-[#00538C] rounded-[4px] transition disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
              >
                <WuiIcon type="arrowRight" size="s" />
                {isRequestingOtp
                  ? 'Mengirim...'
                  : otpCooldown > 0
                  ? `Kirim Ulang (${otpCooldown}s)`
                  : 'Kirim Kode Verifikasi'}
              </button>
            </div>

            {otpMessage && <WuiCallOut tone="success">{otpMessage}</WuiCallOut>}
            {otpError && <WuiCallOut tone="danger">{otpError}</WuiCallOut>}

            <form onSubmit={handleVerifyOtp} className="flex items-center gap-2 max-w-md">
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="000000"
                value={otpInput}
                onChange={(e) => setOtpInput(e.target.value.replace(/\D/g, ''))}
                className="w-36 h-9 px-3 text-[14px] font-mono font-semibold tracking-[6px] text-center bg-white border border-[#D3DAE6] rounded-[4px] focus:outline-none focus:border-[#006BB4]"
              />
              <button
                type="submit"
                disabled={isVerifyingOtp || otpInput.trim().length !== 6}
                className="h-9 px-4 text-[12px] font-medium text-white bg-[#007871] hover:bg-[#005E58] rounded-[4px] transition disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
              >
                {isVerifyingOtp ? 'Memverifikasi...' : 'Verifikasi & Buka Akses'}
              </button>
            </form>

            <div className="pt-3 border-t border-[#E9EDF3]">
              <button
                type="button"
                onClick={() => setShowManualToken((prev) => !prev)}
                className="text-[11px] text-[#006BB4] hover:underline cursor-pointer"
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
                    className="flex-1 h-8 px-3 text-[12px] bg-white border border-[#D3DAE6] rounded-[4px] focus:outline-none focus:border-[#006BB4]"
                  />
                  <button
                    type="submit"
                    disabled={isLoggingIn || !loginInput.trim()}
                    className="h-8 px-3 text-[12px] font-medium text-[#1A1C21] bg-[#FAFBFD] border border-[#D3DAE6] hover:bg-[#F0F4F8] rounded-[4px] transition disabled:opacity-50"
                  >
                    {isLoggingIn ? 'Verifikasi...' : 'Login Token'}
                  </button>
                </form>
              )}
            </div>
          </div>
        </WuiPanel>
      )}

      {error && !isAuthRequired && <WuiCallOut tone="danger">{error}</WuiCallOut>}

      {/* Tabel Daftar Kunci */}
      <WuiPanel
        title="Daftar API Access Keys"
        accentColor="#006BB4"
        right={<span className="text-[11px] font-mono text-[#535966]">{visibleKeys.length} keys</span>}
        bodyClassName="p-0"
      >
        {loading ? (
          <div className="p-8 text-center text-[#535966] text-[12px]">Memuat data API Keys...</div>
        ) : visibleKeys.length === 0 ? (
          <div className="p-8 text-center">
            <WuiIcon type="lock" size="l" className="text-[#69707D] mx-auto mb-2" />
            <div className="text-[13px] font-semibold text-[#1A1C21]">Belum ada API Key</div>
            <p className="text-[12px] text-[#535966] mt-1 max-w-sm mx-auto">
              Klik tombol &quot;Generate New Key&quot; untuk membuat kunci akses machine-to-machine pertama.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left text-[12px] text-[#535966] border-b border-[#D3DAE6]">
                  <th className="px-4 py-2.5 font-semibold">Nama Token / Agent</th>
                  <th className="px-4 py-2.5 font-semibold">Prefix</th>
                  <th className="px-4 py-2.5 font-semibold">Scopes</th>
                  <th className="px-4 py-2.5 font-semibold">Dibuat Pada</th>
                  <th className="px-4 py-2.5 font-semibold">Terakhir Digunakan</th>
                  <th className="px-4 py-2.5 font-semibold">Status</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E9EDF3]">
                {visibleKeys.map((k) => (
                  <tr key={k.id} className="hover:bg-[#FAFBFD] transition-colors">
                    <td className="px-4 py-2.5 font-medium text-[#1A1C21]">
                      <div className="flex items-center gap-1.5">
                        <WuiIcon type="lock" size="s" className="text-[#006BB4]" />
                        <span>{k.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-[#535966]">
                      <code>{k.prefix}</code>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1 flex-wrap">
                        {k.scopes.map((s) => (
                          <WuiBadge
                            key={s}
                            tone="default"
                            className="font-mono text-[10px]"
                          >
                            {s}
                          </WuiBadge>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono tabular-nums text-[11px] text-[#535966]">
                      {formatWazuhTime(k.created_at)}
                    </td>
                    <td className="px-4 py-2.5 font-mono tabular-nums text-[11px] text-[#535966]">
                      {k.last_used_at ? formatWazuhTime(k.last_used_at) : '(Belum pernah)'}
                    </td>
                    <td className="px-4 py-2.5">
                      <WuiHealth tone="success">Active</WuiHealth>
                    </td>
                    <td className="px-4 py-2.5 text-right whitespace-nowrap">
                      <div className="inline-flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => handleRotateKey(k.id, k.name)}
                          disabled={rotatingId === k.id || revokingId === k.id}
                          className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[#006BB4] hover:bg-[#EBF5FB] rounded-[4px] transition disabled:opacity-50 cursor-pointer"
                          title="Putar (rotate) token ini dengan token baru"
                        >
                          <WuiIcon type="refresh" size="s" className={rotatingId === k.id ? 'animate-spin' : ''} />
                          <span>{rotatingId === k.id ? 'Rotating...' : 'Rotate'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleRevokeKey(k.id, k.name)}
                          disabled={revokingId === k.id || rotatingId === k.id}
                          className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[#BD271E] hover:bg-[#FBECEB] rounded-[4px] transition disabled:opacity-50 cursor-pointer"
                          title="Cabut dan hapus akses token ini"
                        >
                          <WuiIcon type="trash" size="s" />
                          <span>{revokingId === k.id ? 'Memproses...' : 'Revoke'}</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </WuiPanel>

      {/* Panduan Cuplikan Kode Integrasi */}
      <div className="bg-white border border-[#D3DAE6] rounded-[4px] overflow-hidden">
        <button
          type="button"
          onClick={() => setIsGuideOpen(!isGuideOpen)}
          className="w-full px-4 py-2.5 bg-[#FAFBFD] hover:bg-[#F0F4F8] flex items-center justify-between text-left transition cursor-pointer"
        >
          <div className="flex items-center gap-2">
            <WuiIcon type="appCode" size="m" className="ouiIcon--mono text-[#006BB4]" />
            <span className="text-[13px] font-semibold text-[#1A1C21]">
              Panduan Integrasi AI Agent, Prompt Setup &amp; Cuplikan Kode
            </span>
            <span className="text-[11px] text-[#535966] hidden sm:inline">
              (Format Bearer Token, cuplikan cURL, dan template prompt untuk agent otonom)
            </span>
          </div>
          <div className="flex items-center gap-1 text-[12px] text-[#006BB4] font-medium">
            <span>{isGuideOpen ? 'Sembunyikan' : 'Lihat Panduan'}</span>
            <WuiIcon type={isGuideOpen ? 'arrowUp' : 'arrowDown'} size="m" />
          </div>
        </button>

        {isGuideOpen && (
          <div className="p-4 space-y-4 border-t border-[#E9EDF3] bg-white">
            <p className="text-[12px] text-[#535966]">
              Salin cuplikan atau prompt di bawah ini untuk menghubungkan skrip automasi maupun AI Agent Anda ke SOAR Control Plane:
            </p>

            <WuiCodeBlock
              label="1. Format Header HTTP Autentikasi (Bearer Token):"
              code="Authorization: Bearer soar_live_xxxxxxxxxxxxxxxxxxxxxxxx"
              helperText="Gunakan header ini di setiap panggilan API untuk mengidentifikasi agen."
            />

            <WuiCodeBlock
              label="2. Cuplikan cURL Baca Riwayat Ancaman & IoC (Scope: read:intel):"
              code='curl -s -H "Authorization: Bearer <API_KEY>" https://soar.raviarnan.dev/api/events/history?limit=10'
              helperText="Mengembalikan ringkasan deteksi FIM, reputasi multi-sumber, dan analisis reasoning."
            />

            <WuiCodeBlock
              label="3. Cuplikan cURL Eksekusi Karantina File (Scope: write:actions):"
              code='curl -s -X POST -H "Authorization: Bearer <API_KEY>" -H "Content-Type: application/json" -d "{\"agent_id\":\"003\",\"action\":\"quarantine\",\"target\":\"/tmp/malware.exe\"}" https://soar.raviarnan.dev/api/commands'
              helperText="Mengirimkan instruksi isolasi file langsung ke agen endpoint via Active Response."
            />

            <WuiCodeBlock
              label="4. Panduan Prompt Setup AI Agent (System / Setup Prompt):"
              code={AI_AGENT_SETUP_PROMPT}
              multiline
              helperText="Tempelkan prompt ini ke instruksi sistem AI Agent (MCP, n8n AI Agent, Claude, atau bot otonom) lalu ganti <SOAR_API_KEY> dengan token yang baru dibuat."
            />
          </div>
        )}
      </div>

      {/* Modal Buat Key Baru */}
      {isCreateModalOpen && (
        <WuiModal
          title={
            <>
              <WuiIcon type="lock" size="m" className="text-[#006BB4]" />
              <span>Generate New API Key</span>
            </>
          }
          onClose={() => setIsCreateModalOpen(false)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="px-3 py-1.5 text-[12px] font-medium text-[#535966] border border-[#D3DAE6] bg-white hover:bg-[#FAFBFD] rounded-[4px] transition cursor-pointer"
              >
                Batal
              </button>
              <button
                type="submit"
                form="create-api-key-form"
                disabled={isSubmitting || selectedScopes.length === 0}
                className="px-3.5 py-1.5 text-[12px] font-medium text-white bg-[#006BB4] hover:bg-[#00538C] rounded-[4px] transition disabled:opacity-50 cursor-pointer"
              >
                {isSubmitting ? 'Membuat...' : 'Buat API Key'}
              </button>
            </>
          }
        >
          <form id="create-api-key-form" onSubmit={handleCreateKey} className="space-y-4">
            <div>
              <label className="block text-[12px] font-medium text-[#1A1C21] mb-1">
                Nama Token / Agent
              </label>
              <input
                type="text"
                required
                placeholder="SOAR Triage Agent, Auto Containment Bot"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                className="w-full h-8 px-3 text-[12px] bg-white border border-[#D3DAE6] rounded-[4px] focus:outline-none focus:border-[#006BB4]"
              />
            </div>

            <div>
              <label className="block text-[12px] font-medium text-[#1A1C21] mb-2">
                Cakupan Izin (Scopes)
              </label>
              <div className="space-y-2 text-[12px]">
                <label className="flex items-start gap-2 p-2 border border-[#E9EDF3] rounded-[4px] hover:bg-[#FAFBFD] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes('read:fleet')}
                    onChange={() => handleToggleScope('read:fleet')}
                    className="mt-0.5 rounded-[2px]"
                  />
                  <div>
                    <div className="font-semibold text-[#1A1C21] font-mono text-[11.5px]">read:fleet</div>
                    <div className="text-[11px] text-[#535966]">
                      Membaca status roster agen endpoint, metrik CPU/RAM, dan telemetri kesehatan.
                    </div>
                  </div>
                </label>

                <label className="flex items-start gap-2 p-2 border border-[#E9EDF3] rounded-[4px] hover:bg-[#FAFBFD] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes('read:intel')}
                    onChange={() => handleToggleScope('read:intel')}
                    className="mt-0.5 rounded-[2px]"
                  />
                  <div>
                    <div className="font-semibold text-[#1A1C21] font-mono text-[11.5px]">read:intel</div>
                    <div className="text-[11px] text-[#535966]">
                      Membaca riwayat deteksi ancaman, analisis reasoning AI, dan korelasi hash IoC.
                    </div>
                  </div>
                </label>

                <label className="flex items-start gap-2 p-2 border border-[#E9EDF3] rounded-[4px] hover:bg-[#FAFBFD] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes('write:actions')}
                    onChange={() => handleToggleScope('write:actions')}
                    className="mt-0.5 rounded-[2px]"
                  />
                  <div>
                    <div className="font-semibold text-[#BD271E] font-mono text-[11.5px]">write:actions</div>
                    <div className="text-[11px] text-[#535966]">
                      Mengeksekusi tindakan mitigasi aktif (Karantina file, isolasi sinkhole, scan).
                    </div>
                  </div>
                </label>
              </div>
            </div>
          </form>
        </WuiModal>
      )}

      {/* Modal One-Time Reveal */}
      {revealedKey && (
        <WuiModal
          title={
            <>
              <WuiIcon type="checkInCircleFilled" size="m" className="text-[#017D73]" />
              <span>{revealedKey.rotated_from ? 'API Key Berhasil Dirotate' : 'API Key Berhasil Dibuat'}</span>
            </>
          }
          maxWidth="max-w-lg"
          onClose={() => setRevealedKey(null)}
          footer={
            <button
              type="button"
              onClick={() => setRevealedKey(null)}
              className="px-4 py-1.5 text-[12px] font-medium text-white bg-[#006BB4] hover:bg-[#00538C] rounded-[4px] transition cursor-pointer"
            >
              Selesai &amp; Tutup
            </button>
          }
        >
          <div className="space-y-4">
            <WuiCallOut tone="warning">
              <strong>Penting:</strong> Salin API Key di bawah ini sekarang. Demi keamanan, token rahasia ini tidak akan ditampilkan lagi setelah dialog ditutup.
            </WuiCallOut>

            <div className="space-y-1.5">
              <div className="text-[12px] font-medium text-[#1A1C21]">
                Token Akses untuk <strong>{revealedKey.name}</strong>:
              </div>
              <div className="bg-[#F5F7FA] border border-[#D3DAE6] rounded-[4px] px-3.5 py-2.5 flex items-center justify-between gap-3">
                <code className="font-mono text-[12.5px] text-[#1A1C21] select-all break-all leading-relaxed">
                  {revealedKey.token}
                </code>
                <button
                  type="button"
                  onClick={() => handleCopyModalToken(revealedKey.token)}
                  className="p-1.5 rounded-[4px] bg-white border border-[#D3DAE6] text-[#535966] hover:text-[#006BB4] hover:border-[#006BB4] transition shrink-0 cursor-pointer"
                  title="Salin ke clipboard"
                >
                  {copiedToken ? (
                    <WuiIcon type="check" size="m" className="text-[#017D73]" />
                  ) : (
                    <WuiIcon type="copy" size="m" />
                  )}
                </button>
              </div>
            </div>
          </div>
        </WuiModal>
      )}

      {/* Rotate API Key Confirmation Modal */}
      {rotateTarget && (
        <WuiModal
          title={
            <>
              <WuiIcon type="refresh" size="m" className="text-[#006BB4]" />
              <span>Rotate API Key</span>
            </>
          }
          onClose={() => setRotateTarget(null)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setRotateTarget(null)}
                className="px-3 py-1.5 border border-[#D3DAE6] rounded-[4px] text-[12px] font-medium text-[#535966] hover:bg-[#FAFBFD] transition cursor-pointer"
              >
                Batal
              </button>
              <button
                type="button"
                onClick={executeRotateKey}
                disabled={rotatingId === rotateTarget.id}
                className="px-3 py-1.5 rounded-[4px] text-[12px] font-semibold text-white bg-[#006BB4] hover:bg-[#00538C] transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {rotatingId === rotateTarget.id ? <WuiIcon type="refresh" size="s" className="animate-spin" /> : null}
                <span>Rotate Kunci</span>
              </button>
            </>
          }
        >
          <p className="text-[12px] text-[#535966] leading-relaxed">
            Apakah Anda yakin ingin memutar (rotate) API Key{' '}
            <strong className="text-[#1A1C21] font-mono">{rotateTarget.name}</strong>? Token lama akan langsung dicabut dan digantikan token baru dengan nama serta scope yang sama.
          </p>
        </WuiModal>
      )}

      {/* Revoke API Key Confirmation Modal */}
      {revokeTarget && (
        <WuiModal
          title={
            <>
              <WuiIcon type="alert" size="m" className="text-[#BD271E]" />
              <span>Cabut API Key</span>
            </>
          }
          onClose={() => setRevokeTarget(null)}
          footer={
            <>
              <button
                type="button"
                onClick={() => setRevokeTarget(null)}
                className="px-3 py-1.5 border border-[#D3DAE6] rounded-[4px] text-[12px] font-medium text-[#535966] hover:bg-[#FAFBFD] transition cursor-pointer"
              >
                Batal
              </button>
              <button
                type="button"
                onClick={executeRevokeKey}
                disabled={revokingId === revokeTarget.id}
                className="px-3 py-1.5 rounded-[4px] text-[12px] font-semibold text-white bg-[#BD271E] hover:bg-[#9E1F18] transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {revokingId === revokeTarget.id ? <WuiIcon type="refresh" size="s" className="animate-spin" /> : null}
                <span>Cabut Kunci</span>
              </button>
            </>
          }
        >
          <p className="text-[12px] text-[#535966] leading-relaxed">
            Apakah Anda yakin ingin mencabut (revoke) API Key{' '}
            <strong className="text-[#1A1C21] font-mono">{revokeTarget.name}</strong>? Akses mesin atau agen yang menggunakan token ini akan langsung terputus dan key dihapus dari daftar aktif. Tindakan ini tidak dapat dibatalkan.
          </p>
        </WuiModal>
      )}
    </div>
  );
}
