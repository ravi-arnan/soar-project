'use client';

import React from 'react';
import {
  X,
  LayoutGrid,
  Shield,
  FileCheck,
  Server,
  Box,
  Settings,
  ExternalLink,
} from 'lucide-react';
import { WazuhLogo } from './WazuhLogo';
import type { FleetHealth } from '@/lib/fleet';

interface WazuhSidebarProps {
  isOpen: boolean;
  onClose: () => void;
  activeView: string;
  onSelectView: (viewId: string) => void;
  /** Jumlah agent dari /api/fleet, dipakai untuk badge di menu Agents. */
  agentCount?: number;
  /** Kesehatan stack (n8n / Gemini / Wazuh API) dari /api/fleet. */
  health?: FleetHealth;
}

export function WazuhSidebar({
  isOpen,
  onClose,
  activeView,
  onSelectView,
  agentCount = 0,
  health,
}: WazuhSidebarProps) {
  if (!isOpen) return null;

  const sections = [
    {
      title: 'Wazuh',
      items: [
        { id: 'modules', label: 'Modules', icon: LayoutGrid },
        { id: 'agents', label: 'Agents', icon: Server, badge: String(agentCount) },
      ],
    },
    {
      title: 'Security Information Management',
      items: [
        { id: 'security-events', label: 'Security events', icon: Shield },
        { id: 'integrity-monitoring', label: 'Integrity monitoring', icon: FileCheck },
      ],
    },
    {
      title: 'Threat Detection and Response',
      items: [
        { id: 'threat-intel', label: 'Threat Intel', icon: Box },
      ],
    },
    {
      title: 'Management',
      items: [
        { id: 'settings', label: 'Settings', icon: Settings },
      ],
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 transition-opacity"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="relative w-72 max-w-[85vw] bg-white h-full shadow-2xl flex flex-col z-10 animate-in slide-in-from-left duration-200">
        {/* Drawer Header */}
        <div className="h-12 border-b border-[#D3DAE6] flex items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <WazuhLogo className="h-4 text-[#1A1C21]" width={80} height={19} />
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#F5F7FA] text-[#5A626F] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Drawer Nav Content */}
        <div className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
          {sections.map((section) => (
            <div key={section.title} className="space-y-1">
              <div className="px-3 text-[10px] font-bold uppercase tracking-wider text-[#8A94A6]">
                {section.title}
              </div>
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeView === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        onSelectView(item.id);
                        onClose();
                      }}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded text-[13px] transition-colors ${
                        isActive
                          ? 'bg-[#EBF5FB] text-[#006BB4] font-semibold'
                          : 'text-[#1A1C21] hover:bg-[#F5F7FA]'
                      }`}
                    >
                      <div className="flex items-center gap-2.5">
                        <Icon className={`w-4 h-4 ${isActive ? 'text-[#006BB4]' : 'text-[#5A626F]'}`} />
                        <span>{item.label}</span>
                      </div>
                      {item.badge && (
                        <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-[#F0F4F8] text-[#5A626F]">
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Drawer Footer */}
        <div className="border-t border-[#D3DAE6] p-3 text-[11px] text-[#8A94A6] flex justify-between items-center bg-[#F9FAFC]">
          <span className="flex items-center gap-2">
            <span className="flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full ${health?.n8n ? 'bg-[#00A389]' : 'bg-[#BD271E]'}`}></span>
              n8n
            </span>
            <span className="flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full ${health?.gemini ? 'bg-[#00A389]' : 'bg-[#F5A623]'}`}></span>
              AI
            </span>
            <span className="flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full ${health?.wazuh_api ? 'bg-[#00A389]' : 'bg-[#BD271E]'}`}></span>
              Wazuh
            </span>
          </span>
          <a
            href="https://documentation.wazuh.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-[#006BB4] hover:underline"
          >
            Docs <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>
    </div>
  );
}
