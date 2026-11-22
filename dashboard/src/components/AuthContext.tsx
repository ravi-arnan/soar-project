'use client';

import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { WuiIcon } from '@/components/wui/WuiIcon';

export type AuthRole = 'admin' | 'analyst' | 'viewer';

export interface AuthUser {
  username: string;
  role: AuthRole;
  email?: string;
  name?: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  role: AuthRole | null;
  authenticated: boolean;
  loading: boolean;
  refreshAuth: () => Promise<void>;
  setAuthenticatedUser: (user: AuthUser | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  role: null,
  authenticated: false,
  loading: true,
  refreshAuth: async () => {},
  setAuthenticatedUser: () => {},
  logout: async () => {},
});

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}

type SessionProbeResult = { status: 'ok'; user: AuthUser | null } | { status: 'redirect' };

async function probeSession(): Promise<SessionProbeResult> {
  const res = await fetch('/api/auth/me', { cache: 'no-store', redirect: 'manual' });
  if (res.type === 'opaqueredirect') {
    return { status: 'redirect' };
  }
  if (!res.ok) {
    return { status: 'ok', user: null };
  }
  const data = (await res.json()) as { authenticated?: boolean; user?: AuthUser | null };
  return { status: 'ok', user: data.authenticated && data.user ? data.user : null };
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshAuth = useCallback(async () => {
    try {
      const result = await probeSession();
      if (result.status === 'redirect') {
        window.location.reload();
        return;
      }
      setUser(result.user);
      setLoading(false);
    } catch {
      setUser(null);
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
        redirect: 'manual',
      });
      if (res.type === 'opaqueredirect') {
        window.location.reload();
        return;
      }
      const data = await res.json().catch(() => null);
      if (data && typeof data.logoutUrl === 'string' && data.logoutUrl) {
        window.location.assign(data.logoutUrl);
        return;
      }
      setUser(null);
      setLoading(false);
    } catch {
      setUser(null);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    probeSession()
      .then((result) => {
        if (cancelled) return;
        if (result.status === 'redirect') {
          window.location.reload();
          return;
        }
        setUser(result.user);
        setLoading(false);
      })
      .catch(() => {
        if (!cancelled) {
          setUser(null);
          setLoading(false);
        }
      });

    const handlePageShow = (event: PageTransitionEvent) => {
      if (event.persisted) {
        setLoading(true);
        void refreshAuth();
      }
    };
    window.addEventListener('pageshow', handlePageShow);

    return () => {
      cancelled = true;
      window.removeEventListener('pageshow', handlePageShow);
    };
  }, [refreshAuth]);

  return (
    <AuthContext.Provider
      value={{
        user,
        role: user?.role ?? null,
        authenticated: Boolean(user),
        loading,
        refreshAuth,
        setAuthenticatedUser: setUser,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function LoginGate() {
  const { setAuthenticatedUser, refreshAuth } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = (await res.json().catch(() => ({}))) as {
        success?: boolean;
        user?: AuthUser;
        error?: string;
      };
      if (!res.ok || !data.success || !data.user) {
        setError(data.error || `Login gagal (HTTP ${res.status})`);
        return;
      }
      setAuthenticatedUser(data.user);
      await refreshAuth();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Gagal menghubungi server autentikasi');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#FAFBFD] flex items-center justify-center p-4">
      <div className="w-full max-w-[400px] bg-white border border-[#D3DAE6] rounded-[4px] shadow-[0_2px_12px_rgba(0,0,0,0.06)] overflow-hidden">
        <div className="bg-[#0B192C] px-6 py-5 text-white flex items-center gap-3">
          <div className="w-9 h-9 rounded-[4px] bg-[#006BB4] flex items-center justify-center shrink-0">
            <WuiIcon type="securityApp" size="l" className="text-white" />
          </div>
          <div>
            <h1 className="text-[16px] font-semibold tracking-tight">SOAR Security Console</h1>
            <p className="text-[12px] text-[#98A2B3]">Masuk untuk mengakses telemetri & Active Response</p>
          </div>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="border border-[#F5C2C0] bg-[#FDF3F2] text-[#BD271E] text-[12px] rounded-[4px] px-3 py-2">
              {error}
            </div>
          )}
          <div>
            <label className="block text-[12px] font-semibold text-[#1A1C21] mb-1">Username</label>
            <input
              type="text"
              required
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 text-[13px] border border-[#D3DAE6] rounded-[4px] focus:outline-none focus:border-[#006BB4]"
            />
          </div>
          <div>
            <label className="block text-[12px] font-semibold text-[#1A1C21] mb-1">Password</label>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 text-[13px] border border-[#D3DAE6] rounded-[4px] focus:outline-none focus:border-[#006BB4]"
            />
          </div>
          <button
            type="submit"
            disabled={submitting}
            className="w-full py-2 px-4 text-[13px] font-semibold text-white bg-[#006BB4] hover:bg-[#005591] disabled:opacity-50 rounded-[4px] transition-colors cursor-pointer"
          >
            {submitting ? 'Memverifikasi...' : 'Sign in'}
          </button>
          <p className="text-[11px] text-[#69707D] leading-relaxed">
            Mendukung autentikasi lokal (RBAC) dan Cloudflare Zero Trust Access SSO terverifikasi JWT.
          </p>
        </form>
      </div>
    </div>
  );
}
