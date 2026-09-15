'use client';

import React from 'react';
import { Menu, ChevronDown, Bell, HelpCircle, MoreVertical, Globe } from 'lucide-react';
import { WazuhLogo } from './WazuhLogo';

interface WazuhHeaderProps {
  breadcrumbs: { label: string; href?: string; onClick?: () => void }[];
  onToggleSidebar: () => void;
  /** true kalau backend fleet-monitor terjangkau (dot API hijau/merah). */
  online?: boolean;
}

export function WazuhHeader({ breadcrumbs, onToggleSidebar, online = true }: WazuhHeaderProps) {
  return (
    <header className="h-12 bg-white border-b border-[#D3DAE6] flex items-center justify-between px-4 sticky top-0 z-40 select-none">
      {/* Left side: Hamburger, Logo, Breadcrumbs */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="p-1.5 rounded hover:bg-[#F0F4F8] text-[#1A1C21] transition-colors"
          title="Toggle navigation"
        >
          <Menu className="w-5 h-5 text-[#1A1C21]" />
        </button>

        <div className="flex items-center gap-1 cursor-pointer" onClick={() => breadcrumbs[0]?.onClick?.()}>
          <WazuhLogo className="h-[18px] text-[#1A1C21]" width={88} height={21} />
          <ChevronDown className="w-3.5 h-3.5 text-[#5A626F]" />
        </div>

        <div className="flex items-center gap-1.5 text-[13px] text-[#5A626F]">
          <span className="text-[#8A94A6]">/</span>
          {breadcrumbs.map((crumb, idx) => (
            <React.Fragment key={crumb.label}>
              {idx > 0 && <span className="text-[#8A94A6]">/</span>}
              {crumb.onClick ? (
                <button
                  onClick={crumb.onClick}
                  className={`hover:text-[#006BB4] hover:underline font-medium ${
                    idx === breadcrumbs.length - 1 ? 'text-[#1A1C21]' : 'text-[#5A626F]'
                  }`}
                >
                  {crumb.label}
                </button>
              ) : (
                <span
                  className={idx === breadcrumbs.length - 1 ? 'text-[#1A1C21] font-medium' : 'text-[#5A626F]'}
                >
                  {crumb.label}
                </span>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Right side: API, default tenant, icons */}
      <div className="flex items-center gap-3">
        <div
          className="flex items-center gap-1 text-[12px] text-[#5A626F] bg-[#F5F7FA] px-2 py-0.5 rounded border border-[#D3DAE6]"
          title={online ? 'Fleet API terhubung' : 'Fleet API tidak terjangkau'}
        >
          <span
            className={`w-2 h-2 rounded-full ${online ? 'bg-[#00A389]' : 'bg-[#BD271E]'}`}
          ></span>
          <span className="font-semibold text-[#1A1C21]">API</span>
        </div>

        <button className="flex items-center gap-1 text-[13px] text-[#1A1C21] hover:bg-[#F5F7FA] px-2 py-1 rounded transition-colors">
          <span>default</span>
          <ChevronDown className="w-3.5 h-3.5 text-[#5A626F]" />
        </button>

        <div className="flex items-center gap-1 text-[#5A626F]">
          <button className="p-1.5 rounded hover:bg-[#F5F7FA] text-[#5A626F]" title="Help">
            <HelpCircle className="w-4 h-4" />
          </button>
          <button className="p-1.5 rounded hover:bg-[#F5F7FA] text-[#5A626F]" title="Notifications">
            <Bell className="w-4 h-4" />
          </button>
          <button className="p-1.5 rounded hover:bg-[#F5F7FA] text-[#5A626F]" title="More">
            <MoreVertical className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
