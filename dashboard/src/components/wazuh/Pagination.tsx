'use client';

import React from 'react';

interface PaginationProps {
  /** Halaman aktif (0-based). */
  page: number;
  pageCount: number;
  total: number;
  rowsPerPage: number;
  rowsOptions?: number[];
  onPageChange: (page: number) => void;
  onRowsChange: (rows: number) => void;
}

/** Footer paginasi bersama (diekstrak dari tabel yang tadinya menduplikasi). */
export function Pagination({
  page,
  pageCount,
  total,
  rowsPerPage,
  rowsOptions = [10, 25, 50],
  onPageChange,
  onRowsChange,
}: PaginationProps) {
  const safePage = Math.min(page, Math.max(0, pageCount - 1));
  const from = total === 0 ? 0 : safePage * rowsPerPage + 1;
  const to = Math.min(safePage * rowsPerPage + rowsPerPage, total);

  return (
    <div className="flex items-center justify-between mt-3 text-[12px] text-[#5A626F]">
      <div className="flex items-center gap-2">
        <span>Rows per page:</span>
        <select
          value={rowsPerPage}
          onChange={(e) => {
            onRowsChange(Number(e.target.value));
            onPageChange(0);
          }}
          className="border border-[#D3DAE6] rounded px-1.5 py-0.5 bg-white text-[#1A1C21] outline-none"
        >
          {rowsOptions.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <span>
          {from}-{to} dari {total}
        </span>
      </div>

      <div className="flex items-center gap-1.5">
        <button
          onClick={() => onPageChange(Math.max(0, safePage - 1))}
          disabled={safePage === 0}
          className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] disabled:opacity-40 disabled:hover:bg-transparent"
          aria-label="Halaman sebelumnya"
        >
          ‹
        </button>
        <span className="font-semibold text-[#006BB4] px-1">
          {safePage + 1} / {Math.max(1, pageCount)}
        </span>
        <button
          onClick={() => onPageChange(Math.min(pageCount - 1, safePage + 1))}
          disabled={safePage >= pageCount - 1}
          className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] disabled:opacity-40 disabled:hover:bg-transparent"
          aria-label="Halaman berikut"
        >
          ›
        </button>
      </div>
    </div>
  );
}
