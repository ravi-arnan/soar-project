'use client';

import React from 'react';
import { WuiIcon, type WuiIconType } from '../wui/WuiIcon';
import { WazuhLogo } from './WazuhLogo';
import { useAuth } from '../AuthContext';
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

export const WazuhSidebar = React.memo(function WazuhSidebar({
  isOpen,
  onClose,
  activeView,
  onSelectView,
  agentCount = 0,
  health,
}: WazuhSidebarProps) {
  const { user } = useAuth();
  if (!isOpen) return null;

  const isAdmin = user?.role === 'admin';
  const opsItems: Array<{ id: string; label: string; icon: WuiIconType; badge?: string }> = [
    { id: 'network-map', label: 'Network map', icon: 'graphApp' },
    ...(isAdmin
      ? [
          { id: 'users', label: 'User Management', icon: 'usersRolesApp' as WuiIconType },
          { id: 'api-keys', label: 'API Keys', icon: 'lock' as WuiIconType },
        ]
      : []),
    { id: 'settings', label: 'Settings', icon: 'gear' },
  ];

  const sections: Array<{
    title: string;
    items: Array<{ id: string; label: string; icon: WuiIconType; badge?: string }>;
  }> = [
    {
      title: 'Wazuh',
      items: [
        { id: 'modules', label: 'Modules', icon: 'lensApp' },
        { id: 'agents', label: 'Agents', icon: 'spacesApp', badge: String(agentCount) },
        { id: 'agent-deployment', label: 'Agent Deployment', icon: 'plusInCircle' },
      ],
    },
    {
      title: 'Security Information Management',
      items: [
        { id: 'security-events', label: 'Security events', icon: 'securityAnalyticsApp' },
        { id: 'integrity-monitoring', label: 'Integrity monitoring', icon: 'sqlApp' },
      ],
    },
    {
      title: 'Threat Detection and Response',
      items: [
        { id: 'threat-intel', label: 'Threat Intel', icon: 'indexRollupApp' },
        { id: 'mitre', label: 'MITRE ATT&CK', icon: 'grokApp' },
      ],
    },
    {
      title: 'Operations & Management',
      items: opsItems,
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
      <div className="relative w-72 max-w-[85vw] bg-white h-full shadow-[4px_0_24px_rgba(0,0,0,0.16)] border-r border-[#D3DAE6] flex flex-col z-10 animate-in slide-in-from-left duration-200">
        {/* Drawer Header */}
        <div className="h-12 border-b border-[#D3DAE6] flex items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <WazuhLogo className="h-4 text-[#1A1C21]" width={80} height={19} />
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-[4px] hover:bg-[#F5F7FA] text-[#535966] transition-colors"
            aria-label="Tutup menu"
          >
            <WuiIcon type="cross" size="m" />
          </button>
        </div>

        {/* Drawer Nav Content */}
        <div className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
          {sections.map((section) => (
            <div key={section.title} className="space-y-1">
              <div className="px-3 text-[11px] font-semibold text-[#69707D]">
                {section.title}
              </div>
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const isActive = activeView === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        onSelectView(item.id);
                        onClose();
                      }}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-[4px] text-[13px] transition-colors ${
                        isActive
                          ? 'bg-[#EBF5FB] text-[#006BB4] font-semibold'
                          : 'text-[#1A1C21] hover:bg-[#F5F7FA]'
                      }`}
                    >
                      <div className="flex items-center gap-2.5">
                        <WuiIcon
                          type={item.icon}
                          size="m"
                          className={isActive ? 'ouiIcon--mono text-[#006BB4]' : 'text-[#535966]'}
                        />
                        <span>{item.label}</span>
                      </div>
                      {item.badge && (
                        <span className="text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded-[4px] bg-[#F5F7FA] text-[#535966]">
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
        <div className="border-t border-[#D3DAE6] p-3 text-[11px] text-[#535966] flex justify-between items-center bg-[#FAFBFD]">
          <span className="flex items-center gap-2.5">
            <span>
              n8n:{' '}
              <span className={health?.n8n ? 'text-[#017D73] font-medium' : 'text-[#BD271E] font-medium'}>
                {health?.n8n ? 'On' : 'Off'}
              </span>
            </span>
            <span>
              AI:{' '}
              <span className={health?.gemini ? 'text-[#017D73] font-medium' : 'text-[#935E00] font-medium'}>
                {health?.gemini ? 'Ready' : 'Warn'}
              </span>
            </span>
            <span>
              Wazuh:{' '}
              <span className={health?.wazuh_api ? 'text-[#017D73] font-medium' : 'text-[#BD271E] font-medium'}>
                {health?.wazuh_api ? 'On' : 'Off'}
              </span>
            </span>
          </span>
          <a
            href="https://documentation.wazuh.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-[#006BB4] hover:underline"
          >
            Docs <WuiIcon type="popout" size="xs" />
          </a>
        </div>
      </div>
    </div>
  );
});
