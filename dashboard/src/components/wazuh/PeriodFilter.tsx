'use client';

import React from 'react';
import type { HistorySource, PeriodPreset, PeriodValue } from '@/lib/fleet';

const PRESETS: Array<{ label: string; value: PeriodPreset }> = [
  { label: 'Semua waktu', value: 'all' },
  { label: '24 jam terakhir', value: '24h' },
  { label: '7 hari terakhir', value: '7d' },
  { label: '30 hari terakhir', value: '30d' },
  { label: '90 hari terakhir', value: '90d' },
  { label: 'Custom rentang', value: 'custom' },
];

const SOURCES: Array<{ label: string; value: HistorySource }> = [
  { label: 'Semua sumber', value: 'all' },
  { label: 'Pipeline SOAR', value: 'soar' },
  { label: 'Wazuh (indexer)', value: 'wazuh' },
];

interface PeriodFilterProps {
  value: PeriodValue;
  onChange: (value: PeriodValue) => void;
  /** Filter sumber riwayat (opsional). */
  source?: HistorySource;
  onSourceChange?: (source: HistorySource) => void;
}

function dateInputValue(iso: string | null): string {
  return iso ? iso.slice(0, 10) : '';
}

/** Awal hari (00:00) / akhir hari (23:59:59) lokal -> ISO. */
function dayStartIso(date: string): string | null {
  return date ? new Date(`${date}T00:00:00`).toISOString() : null;
}
function dayEndIso(date: string): string | null {
  return date ? new Date(`${date}T23:59:59.999`).toISOString() : null;
}

/**
 * Kontrol periode bersama (preset 24j/7h/30h/90h/Semua + rentang custom).
 * Dipakai semua view event supaya konsisten.
 */
export function PeriodFilter({ value, onChange, source, onSourceChange }: PeriodFilterProps) {
  const setPreset = (preset: PeriodPreset) => {
    if (preset === 'custom') {
      onChange({ ...value, preset });
    } else {
      onChange({ preset, since: null, until: null });
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <select
        value={value.preset}
        onChange={(e) => setPreset(e.target.value as PeriodPreset)}
        title="Rentang waktu event"
        className="h-9 bg-white border border-[#D3DAE6] rounded px-2 text-[13px] text-[#1A1C21] outline-none cursor-pointer"
      >
        {PRESETS.map((p) => (
          <option key={p.value} value={p.value}>
            {p.label}
          </option>
        ))}
      </select>

      {value.preset === 'custom' && (
        <div className="flex items-center gap-1.5">
          <input
            type="date"
            value={dateInputValue(value.since)}
            max={dateInputValue(value.until) || undefined}
            onChange={(e) => onChange({ ...value, since: dayStartIso(e.target.value) })}
            className="h-9 bg-white border border-[#D3DAE6] rounded px-2 text-[13px] text-[#1A1C21] outline-none"
          />
          <span className="text-[12px] text-[#5A626F]">s/d</span>
          <input
            type="date"
            value={dateInputValue(value.until)}
            min={dateInputValue(value.since) || undefined}
            onChange={(e) => onChange({ ...value, until: dayEndIso(e.target.value) })}
            className="h-9 bg-white border border-[#D3DAE6] rounded px-2 text-[13px] text-[#1A1C21] outline-none"
          />
        </div>
      )}

      {source && onSourceChange && (
        <select
          value={source}
          onChange={(e) => onSourceChange(e.target.value as HistorySource)}
          title="Sumber riwayat"
          className="h-9 bg-white border border-[#D3DAE6] rounded px-2 text-[13px] text-[#1A1C21] outline-none cursor-pointer"
        >
          {SOURCES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}
