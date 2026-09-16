'use client';

/**
 * Data layer untuk dashboard fleet SOAR.
 *
 * Sumber data = `scripts/fleet-monitor.py` (backend stdlib yang sudah jalan di :8080):
 *   GET /api/fleet   -> { generated_at, health, stats, agents[] }
 *   GET /api/events  -> { events: FleetEvent[] }
 *
 * Next.js merewrite `/api/*` ke backend (lihat next.config.ts), jadi fetch
 * di sini same-origin dan tidak butuh CORS.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

export interface FleetAgent {
  id: string;
  name: string;
  type: 'wazuh' | 'rust' | string;
  status: string;
  ip: string;
  version: string;
  lastKeepAlive: string;
  os: string;
  binary: string;
  ram: string;
  last_hash?: string;
  age_sec?: number;
  cpu_pct?: number;
  ram_gb?: { total?: number; used?: number };
}

export interface FleetEvent {
  ts: string;
  agent: string;
  agent_id: string;
  path: string;
  hash: string;
  severity?: string;
  status: string;
  ai?: string;
  url?: string;
  verdict?: string;
}

export interface FleetHealth {
  n8n: boolean;
  gemini: boolean;
  wazuh_api: boolean;
}

export interface FleetSeverityCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  UNVERIFIED: number;
  INFO: number;
}

export interface FleetStats {
  total: number;
  active: number;
  disconnected: number;
  rust: number;
  wazuh: number;
  events_total: number;
  severity: FleetSeverityCounts;
  capacity_demo?: string;
}

export interface FleetSnapshot {
  generated_at: string;
  health: FleetHealth;
  stats: FleetStats;
  agents: FleetAgent[];
}

export const EMPTY_SNAPSHOT: FleetSnapshot = {
  generated_at: '',
  health: { n8n: false, gemini: false, wazuh_api: false },
  stats: {
    total: 0,
    active: 0,
    disconnected: 0,
    rust: 0,
    wazuh: 0,
    events_total: 0,
    severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, UNVERIFIED: 0, INFO: 0 },
  },
  agents: [],
};

/** Urutan severity dari paling berat, dipakai untuk sorting & filtering. */
export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'UNVERIFIED', 'INFO'] as const;

/**
 * Peta severity fleet -> level alert Wazuh (skala 0-15) supaya badge level di
 * tabel security events tetap konsisten dengan desain Wazuh.
 */
export const SEVERITY_LEVEL: Record<string, number> = {
  CRITICAL: 12,
  HIGH: 8,
  MEDIUM: 5,
  UNVERIFIED: 4,
  INFO: 3,
};

export function severityLevel(sev?: string): number {
  return SEVERITY_LEVEL[(sev || 'INFO').toUpperCase()] ?? 3;
}

/** linux | windows | mac — untuk ikon OS di komponen. */
export function osType(os: string): 'linux' | 'windows' | 'mac' {
  const s = (os || '').toLowerCase();
  if (s.includes('windows')) return 'windows';
  if (s.includes('mac') || s.includes('darwin') || s.includes('os x')) return 'mac';
  return 'linux';
}

/** 'active' | 'disconnected' | 'never_connected' — status yang dikenal komponen Wazuh. */
export function agentStatus(status: string): 'active' | 'disconnected' | 'never_connected' {
  const s = (status || '').toLowerCase();
  if (s === 'active') return 'active';
  if (s === 'never_connected' || s === 'never connected' || s === 'pending') {
    return 'never_connected';
  }
  return 'disconnected';
}

/** Format timestamp ISO -> "Jan 24, 2026 @ 09:32:55" ala Wazuh. */
export function formatWazuhTime(iso: string): string {
  if (!iso || iso === '-') return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const date = d.toLocaleDateString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
  });
  const time = d.toLocaleTimeString('en-GB', { hour12: false });
  return `${date} @ ${time}`;
}

/** "09:12:38" untuk kolom tabel ringkas. */
export function formatClock(iso: string): string {
  if (!iso || iso === '-') return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return (await res.json()) as T;
}

export async function fetchSnapshot(): Promise<{
  snapshot: FleetSnapshot;
  events: FleetEvent[];
}> {
  const [snapshot, eventsRes] = await Promise.all([
    getJson<FleetSnapshot>('/api/fleet'),
    getJson<{ events: FleetEvent[] }>('/api/events'),
  ]);
  return { snapshot, events: eventsRes.events || [] };
}

export interface UseFleetResult {
  snapshot: FleetSnapshot;
  events: FleetEvent[];
  loading: boolean;
  error: string | null;
  online: boolean;
  refresh: () => void;
}

/**
 * Poll `/api/fleet` + `/api/events` secara berkala (default 5s, sama dengan
 * auto-refresh dashboard lama). Kalau backend mati, snapshot terakhir tetap
 * ditampilkan dan `error` diisi.
 */
export function useFleet(pollMs = 5000): UseFleetResult {
  const [snapshot, setSnapshot] = useState<FleetSnapshot>(EMPTY_SNAPSHOT);
  const [events, setEvents] = useState<FleetEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [online, setOnline] = useState(false);
  const inFlight = useRef(false);

  const load = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const data = await fetchSnapshot();
      setSnapshot(data.snapshot);
      setEvents(data.events);
      setOnline(true);
      setError(null);
    } catch (e) {
      setOnline(false);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      inFlight.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // setTimeout(0) menunda fetch pertama keluar dari body effect supaya tidak
    // memicu setState sinkron saat render (react-hooks/set-state-in-effect).
    const kickoff = setTimeout(load, 0);
    const timer = setInterval(load, pollMs);
    return () => {
      clearTimeout(kickoff);
      clearInterval(timer);
    };
  }, [load, pollMs]);

  return { snapshot, events, loading, error, online, refresh: load };
}
