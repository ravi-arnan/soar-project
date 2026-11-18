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
export const Pagination = React.memo(function Pagination({
  page,
  pageCount,
  total,
  rowsPerPage,
  rowsOptions = [10, 25, 50],
  onPageChange,
  onRowsChange,
}: PaginationProps) {
  const isAll = rowsPerPage <= 0;
  const effectivePageCount = isAll ? 1 : Math.max(1, pageCount);
  const safePage = Math.min(page, Math.max(0, effectivePageCount - 1));
  const from = total === 0 ? 0 : isAll ? 1 : safePage * rowsPerPage + 1;
  const to = isAll ? total : Math.min(safePage * rowsPerPage + rowsPerPage, total);

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
              {n <= 0 ? 'All' : n}
            </option>
          ))}
        </select>
        <span>
          {from}-{to} dari {total}
        </span>
      </div>

      <div className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={() => onPageChange(Math.max(0, safePage - 1))}
          disabled={safePage === 0}
          className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] disabled:opacity-40 disabled:hover:bg-transparent cursor-pointer disabled:cursor-default"
          aria-label="Halaman sebelumnya"
        >
          ‹
        </button>
        <span className="font-semibold text-[#006BB4] px-1">
          {safePage + 1} / {effectivePageCount}
        </span>
        <button
          type="button"
          onClick={() => onPageChange(Math.min(effectivePageCount - 1, safePage + 1))}
          disabled={safePage >= effectivePageCount - 1}
          className="px-2 py-0.5 rounded hover:bg-[#F5F7FA] disabled:opacity-40 disabled:hover:bg-transparent cursor-pointer disabled:cursor-default"
          aria-label="Halaman berikut"
        >
          ›
        </button>
      </div>
    </div>
  );
});
