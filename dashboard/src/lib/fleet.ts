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
  regDate?: string;
  watch_paths?: string[];
}

export interface FleetEvent {
  id?: string;
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
  /** Asal riwayat: 'soar' (pipeline, ter-enrich) atau 'wazuh' (indexer). */
  source?: 'soar' | 'wazuh';
  rule_id?: string;
  rule_level?: number;
  rule_desc?: string;
}

/** Satu file dalam laporan scan on-demand (`/api/scan-results`). */
export interface FleetScanFile {
  path: string;
  size: number;
  sha256: string;
  /** true = hash belum pernah terlihat (cache-first), false = sudah dikenal. */
  new?: boolean;
}

/** Ringkasan scan on-demand 1 agent (bukan alert per-file). */
export interface FleetScanResult {
  agent_id: string;
  agent_name: string;
  path: string;
  started: string;
  finished: string;
  elapsed_ms: number;
  scanned: number;
  new_hashes: number;
  known_hashes: number;
  total_bytes: number;
  truncated: boolean;
  files?: FleetScanFile[];
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

/** Format timestamp ISO -> "Jan 24, 2026 @ 09:32:55" ala Wazuh (WITA). */
export function formatWazuhTime(iso: string): string {
  if (!iso || iso === '-') return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const date = d.toLocaleDateString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    timeZone: 'Asia/Makassar',
  });
  const time = d.toLocaleTimeString('en-GB', { hour12: false, timeZone: 'Asia/Makassar' });
  return `${date} @ ${time}`;
}

/** "09:12:38" untuk kolom tabel ringkas (WITA). */
export function formatClock(iso: string): string {
  if (!iso || iso === '-') return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString('en-GB', { hour12: false, timeZone: 'Asia/Makassar' });
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
  // 000 wazuh.manager adalah server itu sendiri (self-loopback), bukan agent:
  // keluarkan dari daftar + hitung ulang stats supaya dashboard hanya bicara
  // soal endpoint. Status manager tetap terpantau via health (Stack health).
  const agents = (snapshot.agents || []).filter((a) => a.id !== '000');
  const active = agents.filter((a) => (a.status || '').toLowerCase() === 'active').length;
  snapshot.agents = agents;
  snapshot.stats = {
    ...snapshot.stats,
    total: agents.length,
    active,
    disconnected: agents.length - active,
    rust: agents.filter((a) => a.type === 'rust').length,
    wazuh: agents.filter((a) => a.type === 'wazuh').length,
  };
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

// --- Riwayat event per periode (/api/events/history) ----------------------
// Sumber gabungan: event pipeline SOAR (SQLite di fleet-monitor) + alert Wazuh
// historis (indexer). Dipakai view "minggu/bulan/custom" di semua halaman event.

export type PeriodPreset = '24h' | '7d' | '30d' | '90d' | 'all' | 'custom';
export type HistorySource = 'all' | 'soar' | 'wazuh';

export interface TimeWindow {
  /** ISO; null = tanpa batas bawah. */
  since: string | null;
  /** ISO; null = sekarang. */
  until: string | null;
}

export const DEFAULT_HISTORY_LIMIT = 100;

const PRESET_HOURS: Record<'24h' | '7d' | '30d' | '90d', number> = {
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30,
  '90d': 24 * 90,
};

/** Ubah preset periode -> rentang {since, until}. 'all' / 'custom' = tanpa batas. */
export function rangeToWindow(preset: PeriodPreset, now: Date = new Date()): TimeWindow {
  if (preset === 'all' || preset === 'custom') return { since: null, until: null };
  const hours = PRESET_HOURS[preset];
  return { since: new Date(now.getTime() - hours * 3600 * 1000).toISOString(), until: null };
}

export interface EventHistoryQuery {
  since?: string | null;
  until?: string | null;
  limit?: number;
  offset?: number;
  severity?: string[];
  agentId?: string;
  /** Token pencarian; tiap token AND (dikirim sebagai `q` berulang). */
  q?: string[];
  source?: HistorySource;
  dedup?: boolean;
}

/** Nilai kontrol periode yang dipegang UI (preset + rentang custom). */
export interface PeriodValue {
  preset: PeriodPreset;
  since: string | null;
  until: string | null;
}

export const DEFAULT_PERIOD: PeriodValue = { preset: 'all', since: null, until: null };

/** Ubah nilai kontrol periode -> rentang query {since, until}. */
export function periodToWindow(value: PeriodValue): TimeWindow {
  if (value.preset === 'custom') return { since: value.since, until: value.until };
  return rangeToWindow(value.preset);
}

export interface EventHistoryStats {
  severity: FleetSeverityCounts;
  daily: Array<{ date: string; count: number }>;
  top_agents: Array<{ key: string; count: number }>;
  top_paths: Array<{ key: string; count: number }>;
}

export interface EventHistoryResult {
  events: FleetEvent[];
  total: number;
  limit: number;
  offset: number;
  took_ms: number;
  indexer_ok: boolean | null;
  sources: { soar: number; wazuh: number };
  stats: EventHistoryStats;
}

export const EMPTY_HISTORY_STATS: EventHistoryStats = {
  severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, UNVERIFIED: 0, INFO: 0 },
  daily: [],
  top_agents: [],
  top_paths: [],
};

/** Bangun query-string untuk `/api/events/history` (deterministik, mudah diuji). */
export function buildHistoryQuery(query: EventHistoryQuery): string {
  const params = new URLSearchParams();
  if (query.since) params.set('since', query.since);
  if (query.until) params.set('until', query.until);
  params.set('limit', String(query.limit ?? DEFAULT_HISTORY_LIMIT));
  params.set('offset', String(query.offset ?? 0));
  if (query.severity?.length) params.set('severity', query.severity.join(','));
  if (query.agentId) params.set('agent_id', query.agentId);
  for (const token of query.q ?? []) {
    if (token.trim()) params.append('q', token.trim());
  }
  if (query.source) params.set('source', query.source);
  if (query.dedup === false) params.set('dedup', 'false');
  return params.toString();
}

export async function fetchEventHistory(query: EventHistoryQuery): Promise<EventHistoryResult> {
  return getJson<EventHistoryResult>(`/api/events/history?${buildHistoryQuery(query)}`);
}

export interface UseEventHistoryResult {
  events: FleetEvent[];
  stats: EventHistoryStats;
  total: number;
  indexerOk: boolean | null;
  sources: { soar: number; wazuh: number };
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

/**
 * Poll riwayat event untuk rentang/parameter tertentu. `query` sebaiknya
 * dimemo parent; hook bergantung pada query-string hasil serialisasinya.
 */
export function useEventHistory(query: EventHistoryQuery, pollMs = 20000): UseEventHistoryResult {
  const [data, setData] = useState<EventHistoryResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const url = `/api/events/history?${buildHistoryQuery(query)}`;

  const load = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const result = await getJson<EventHistoryResult>(url);
      setData(result);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      inFlight.current = false;
      setLoading(false);
    }
  }, [url]);

  useEffect(() => {
    const kickoff = setTimeout(() => {
      setLoading(true);
      load();
    }, 0);
    const timer = setInterval(load, pollMs);
    return () => {
      clearTimeout(kickoff);
      clearInterval(timer);
    };
  }, [url, load, pollMs]);

  return {
    events: data?.events ?? [],
    stats: data?.stats ?? EMPTY_HISTORY_STATS,
    total: data?.total ?? 0,
    indexerOk: data?.indexer_ok ?? null,
    sources: data?.sources ?? { soar: 0, wazuh: 0 },
    loading,
    error,
    refresh: load,
  };
}
