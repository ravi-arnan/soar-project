import assert from 'node:assert/strict';
import test from 'node:test';
import { rangeToWindow, periodToWindow, buildHistoryQuery, agentRiskMeta } from './fleet.ts';

test('rangeToWindow: preset 24h -> since 24 jam lalu, until null', () => {
  const now = new Date('2026-10-04T00:00:00.000Z');
  const w = rangeToWindow('24h', now);
  assert.equal(w.since, '2026-10-03T00:00:00.000Z');
  assert.equal(w.until, null);
});

test('rangeToWindow: 7d dan 30d', () => {
  const now = new Date('2026-10-04T00:00:00.000Z');
  assert.equal(rangeToWindow('7d', now).since, '2026-09-27T00:00:00.000Z');
  assert.equal(rangeToWindow('30d', now).since, '2026-09-04T00:00:00.000Z');
});

test('rangeToWindow: all -> tanpa batas', () => {
  assert.deepEqual(rangeToWindow('all'), { since: null, until: null });
});

test('periodToWindow: custom memakai since/until eksplisit', () => {
  const w = periodToWindow({ preset: 'custom', since: 'A', until: 'B' });
  assert.deepEqual(w, { since: 'A', until: 'B' });
});

test('periodToWindow: preset selain custom -> dihitung dari jam', () => {
  const w = periodToWindow({ preset: '24h', since: null, until: null });
  assert.equal(w.until, null);
  assert.equal(typeof w.since, 'string');
  assert.ok(new Date(w.since as string).getTime() < Date.now());
});

test('buildHistoryQuery: parameter lengkap + q berulang (AND)', () => {
  const qs = buildHistoryQuery({
    since: '2026-10-01T00:00:00Z',
    until: '2026-10-04T00:00:00Z',
    limit: 25,
    offset: 50,
    severity: ['CRITICAL', 'HIGH'],
    agentId: '009',
    q: ['eicar', 'tmp'],
    source: 'soar',
    dedup: false,
  });
  const p = new URLSearchParams(qs);
  assert.equal(p.get('since'), '2026-10-01T00:00:00Z');
  assert.equal(p.get('until'), '2026-10-04T00:00:00Z');
  assert.equal(p.get('limit'), '25');
  assert.equal(p.get('offset'), '50');
  assert.equal(p.get('severity'), 'CRITICAL,HIGH');
  assert.equal(p.get('agent_id'), '009');
  assert.deepEqual(p.getAll('q'), ['eicar', 'tmp']);
  assert.equal(p.get('source'), 'soar');
  assert.equal(p.get('dedup'), 'false');
});

test('buildHistoryQuery: default limit/offset/omitempat kosong', () => {
  const p = new URLSearchParams(buildHistoryQuery({}));
  assert.equal(p.get('limit'), '100');
  assert.equal(p.get('offset'), '0');
  assert.equal(p.get('since'), null);
  assert.equal(p.get('severity'), null);
  assert.equal(p.get('dedup'), null);
  assert.equal(p.getAll('q').length, 0);
});

test('agentRiskMeta: memetakan low/medium/high dan fallback default', () => {
  assert.deepEqual(agentRiskMeta(undefined), {
    level: 'low',
    label: 'Rendah',
    tone: 'success',
    activeAlerts: 0,
    resolved: 0,
  });
  assert.deepEqual(
    agentRiskMeta({
      level: 'medium',
      score: 20,
      window_days: 7,
      active_alerts: 2,
      critical: 0,
      high: 1,
      medium: 1,
      unverified: 0,
      resolved: 0,
    }),
    { level: 'medium', label: 'Sedang', tone: 'warning', activeAlerts: 2, resolved: 0 },
  );
  assert.deepEqual(
    agentRiskMeta({
      level: 'high',
      score: 60,
      window_days: 7,
      active_alerts: 3,
      critical: 1,
      high: 1,
      medium: 1,
      unverified: 0,
      resolved: 1,
    }),
    { level: 'high', label: 'Tinggi', tone: 'danger', activeAlerts: 3, resolved: 1 },
  );
});
