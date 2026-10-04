'use client';

import React, { useState } from 'react';
import { RefreshCw, Plus } from 'lucide-react';

interface WazuhFilterBarProps {
  onSearch?: (query: string, filters: string[]) => void;
  onRefresh?: () => void;
  initialFilters?: string[];
  /** Slot kontrol periode (PeriodFilter) di baris kontrol. */
  periodSlot?: React.ReactNode;
}

export function WazuhFilterBar({
  onSearch,
  onRefresh,
  initialFilters = [],
  periodSlot,
}: WazuhFilterBarProps) {
  const [query, setQuery] = useState('');
  const [filters, setFilters] = useState<string[]>(initialFilters);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    if (onRefresh) onRefresh();
    setTimeout(() => setIsRefreshing(false), 600);
  };

  /** Kirim query + chip aktif ke parent tiap berubah. */
  const emit = (q: string, f: string[]) => onSearch?.(q, f);

  const updateQuery = (q: string) => {
    setQuery(q);
    emit(q, filters);
  };

  const removeFilter = (index: number) => {
    const next = filters.filter((_, i) => i !== index);
    setFilters(next);
    emit(query, next);
  };

  /** Jadikan teks search saat ini sebagai chip filter (AND dengan search). */
  const addFilter = () => {
    const t = query.trim();
    if (!t || filters.includes(t)) return;
    const next = [...filters, t];
    setFilters(next);
    setQuery('');
    emit('', next);
  };

  return (
    <div className="space-y-2 mb-4">
      {/* Top Search & Controls Row */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Search input group */}
        <div className="flex-1 min-w-[280px] flex items-center bg-white border border-[#D3DAE6] rounded h-9 focus-within:border-[#006BB4] focus-within:ring-1 focus-within:ring-[#006BB4] transition-all">
          <div className="relative flex-1 flex items-center">
            <input
              type="text"
              placeholder="Search"
              value={query}
              onChange={(e) => updateQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') addFilter();
              }}
              className="w-full pl-2.5 pr-12 text-[13px] bg-transparent text-[#1A1C21] outline-none placeholder-[#8A94A6]"
            />
            <span className="absolute right-2 text-[10px] font-bold text-[#5A626F] bg-[#F5F7FA] px-1.5 py-0.5 rounded border border-[#D3DAE6]">
              KQL
            </span>
          </div>
        </div>

        {/* Kontrol periode (disuntik view) */}
        {periodSlot}

        {/* Refresh button */}
        <button
          onClick={handleRefresh}
          className="h-9 px-4 bg-[#006BB4] hover:bg-[#005593] text-white rounded font-medium text-[13px] flex items-center gap-2 transition-colors shadow-sm cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter chips row */}
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        {filters.map((filter, index) => (
          <div
            key={index}
            className="flex items-center gap-1.5 bg-white border border-[#D3DAE6] px-2.5 py-1 rounded text-[#1A1C21]"
          >
            <span className="font-medium">{filter}</span>
            <button
              onClick={() => removeFilter(index)}
              className="text-[#8A94A6] hover:text-[#BD271E] font-bold ml-1"
            >
              ×
            </button>
          </div>
        ))}
        <button
          onClick={addFilter}
          title="Jadikan teks search sebagai chip filter (atau Enter)"
          className="flex items-center gap-1 text-[#006BB4] hover:underline font-medium px-2 py-1"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add filter</span>
        </button>
      </div>
    </div>
  );
}
