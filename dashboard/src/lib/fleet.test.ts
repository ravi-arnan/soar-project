import assert from 'node:assert/strict';
import test from 'node:test';
import { rangeToWindow, periodToWindow, buildHistoryQuery } from './fleet.ts';

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
