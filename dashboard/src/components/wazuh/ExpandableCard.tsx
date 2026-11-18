'use client';

import React, { useState } from 'react';
import { WuiIcon } from '../wui/WuiIcon';

interface ExpandableCardProps {
  /** Judul kartu (header + modal). */
  title: string;
  /** Elemen kanan header selain tombol expand (opsional). */
  actions?: React.ReactNode;
  children: React.ReactNode;
}

/** Kartu gaya Wazuh dengan tombol expand fungsional: isi kartu dibuka ulang
 *  dalam modal fullscreen. Tutup via X, klik backdrop, atau Escape. */
export const ExpandableCard = React.memo(function ExpandableCard({
  title,
  actions,
  children,
}: ExpandableCardProps) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <div className="bg-white border border-[#D3DAE6] rounded p-4 relative">
        <div className="flex items-center justify-between mb-3">
          <div className="text-[13px] font-semibold text-[#1A1C21]">{title}</div>
          <div className="flex items-center gap-2">
            {actions}
            <button
              onClick={() => setOpen(true)}
              title={`Perbesar ${title}`}
              aria-label={`Perbesar ${title}`}
              className="text-[#69707D] hover:text-[#1A1C21] transition-colors"
            >
              <WuiIcon type="fullScreen" size="s" />
            </button>
          </div>
        </div>
        {children}
      </div>
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 lg:p-8"
          onClick={() => setOpen(false)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setOpen(false);
          }}
          role="dialog"
          aria-modal="true"
          aria-label={title}
        >
          <div
            className="bg-white border border-[#D3DAE6] rounded-[4px] w-full max-w-4xl max-h-full overflow-y-auto p-4 lg:p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4 border-b border-[#D3DAE6] pb-2">
              <h2 className="text-[14px] font-semibold text-[#1A1C21]">{title}</h2>
              <button
                onClick={() => setOpen(false)}
                title="Tutup"
                aria-label="Tutup"
                className="p-1 rounded-[4px] hover:bg-[#F5F7FA] text-[#69707D] transition-colors"
              >
                <WuiIcon type="cross" size="m" />
              </button>
            </div>
            {children}
          </div>
        </div>
      )}
    </>
  );
});
