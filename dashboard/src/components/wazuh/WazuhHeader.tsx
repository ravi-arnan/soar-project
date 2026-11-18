'use client';

import React, { useState, useEffect, useRef } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import { WazuhLogo } from './WazuhLogo';
import type {
  FleetHealth,
  FleetStats,
  HistorySource,
  PeriodPreset,
} from '@/lib/fleet';

interface WazuhHeaderProps {
  breadcrumbs: { label: string; href?: string; onClick?: () => void }[];
  onToggleSidebar: () => void;
  /** true kalau backend fleet-monitor terjangkau (dot API hijau/merah). */
  online?: boolean;
  stats?: FleetStats;
  health?: FleetHealth;
  activeView?: string;
  onNavigate?: (
    viewId: string,
    options?: {
      severity?: string[];
      agentId?: string;
      tab?: 'dashboard' | 'events';
      period?: PeriodPreset;
      source?: HistorySource;
    }
  ) => void;
  onRefresh?: () => void;
}

const WZ_TOP_NAV = [
  { id: 'modules', label: 'Overview' },
  { id: 'agents', label: 'Agents' },
  { id: 'agent-deployment', label: 'Deploy agent' },
  { id: 'security-events', label: 'Security events' },
  { id: 'integrity-monitoring', label: 'Integrity monitoring' },
  { id: 'threat-intel', label: 'Threat Intel' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
  { id: 'network-map', label: 'Network map' },
  { id: 'users', label: 'Users' },
  { id: 'api-keys', label: 'API Keys' },
  { id: 'settings', label: 'Settings' },
];

export const WazuhHeader = React.memo(function WazuhHeader({
  breadcrumbs,
  onToggleSidebar,
  online = true,
  stats,
  health,
  activeView,
  onNavigate,
  onRefresh,
}: WazuhHeaderProps) {
  const [activeMenu, setActiveMenu] = useState<
    'api' | 'tenant' | 'user' | 'help' | 'notifications' | 'more' | null
  >(null);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const [currentUser, setCurrentUser] = useState<{
    username: string;
    role: 'admin' | 'analyst' | 'viewer';
    email?: string;
    name?: string;
  } | null>(null);
  const menuContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch('/api/auth/me')
      .then((res) => res.json())
      .then((data) => {
        if (data.authenticated && data.user) {
          setCurrentUser(data.user);
        }
      })
      .catch(() => {});
  }, []);

  const totalThreats =
    (stats?.severity?.CRITICAL || 0) + (stats?.severity?.HIGH || 0);

  // Tutup dropdown saat klik di luar atau saat menekan Escape
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (
        menuContainerRef.current &&
        !menuContainerRef.current.contains(e.target as Node)
      ) {
        setActiveMenu(null);
      }
    }
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setActiveMenu(null);
        setAboutOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const toggleMenu = (menu: 'api' | 'tenant' | 'user' | 'help' | 'notifications' | 'more') => {
    setActiveMenu((prev) => (prev === menu ? null : menu));
  };

  return (
    <>
      <header className="h-12 bg-white border-b border-[#D3DAE6] flex items-center justify-between px-4 sticky top-0 z-40 select-none">
        {/* Left side: Hamburger, Logo, Breadcrumbs */}
        <div className="flex items-center gap-3">
          <button
            onClick={onToggleSidebar}
            className="p-1.5 rounded-[4px] hover:bg-[#F5F7FA] text-[#1A1C21] transition-colors"
            title="Toggle navigation"
            aria-label="Toggle navigation"
          >
            <WuiIcon type="menu" size={18} className="text-[#1A1C21]" />
          </button>

          <div
            className="flex items-center gap-1 cursor-pointer"
            onClick={() => breadcrumbs[0]?.onClick?.()}
          >
            <WazuhLogo className="h-[18px] text-[#1A1C21]" width={88} height={21} />
            <WuiIcon type="arrowDown" size="s" className="text-[#69707D]" />
          </div>

          <div className="flex items-center gap-1.5 text-[13px] text-[#5A626F]">
            <span className="text-[#8A94A6]">/</span>
            {breadcrumbs.map((crumb, idx) => (
              <React.Fragment key={crumb.label}>
                {idx > 0 && <span className="text-[#8A94A6]">/</span>}
                {crumb.onClick ? (
                  <button
                    onClick={crumb.onClick}
                    className={`hover:text-[#006BB4] hover:underline font-medium focus:outline-none focus-visible:ring-1 focus-visible:ring-[#006BB4] focus-visible:ring-offset-1 rounded-xs transition-colors ${
                      idx === breadcrumbs.length - 1 ? 'text-[#1A1C21]' : 'text-[#5A626F]'
                    }`}
                  >
                    {crumb.label}
                  </button>
                ) : (
                  <span
                    className={
                      idx === breadcrumbs.length - 1
                        ? 'text-[#1A1C21] font-medium'
                        : 'text-[#5A626F]'
                    }
                  >
                    {crumb.label}
                  </span>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Right side: API, default tenant, icons */}
        <div ref={menuContainerRef} className="flex items-center gap-2 sm:gap-3 relative">
          {/* 1. Server API Selector (Wazuh WzMenu style: plain icon + label, no green dot) */}
          <div className="relative">
            <button
              onClick={() => toggleMenu('api')}
              className={`flex items-center gap-1.5 text-[12px] px-2 py-1 rounded-[4px] transition-colors ${
                activeMenu === 'api'
                  ? 'bg-[#EBF5FB] text-[#006BB4]'
                  : 'text-[#343741] hover:bg-[#F5F7FA]'
              }`}
              title={online ? 'Fleet API terhubung' : 'Fleet API tidak terjangkau'}
              aria-expanded={activeMenu === 'api'}
            >
              <WuiIcon type="compute" size="s" className={online ? 'text-[#535966]' : 'text-[#BD271E]'} />
              <span className="font-medium text-[#1A1C21]">Server API</span>
              {!online && (
                <span className="text-[11px] font-medium text-[#BD271E]">(Offline)</span>
              )}
              <WuiIcon type="arrowDown" size="s" className="text-[#69707D]" />
            </button>

            {/* API Popover */}
            {activeMenu === 'api' && (
              <div className="absolute right-0 top-full mt-2 w-64 bg-white border border-[#D3DAE6] rounded-[4px] shadow-[0_4px_16px_rgba(0,0,0,0.12)] z-50 py-2">
                <div className="px-3 py-1.5 border-b border-[#E9EDF3] flex items-center justify-between">
                  <span className="text-[12px] font-semibold text-[#343741]">
                    Koneksi backend
                  </span>
                  <span
                    className={`text-[12px] font-medium ${
                      online ? 'text-[#017D73]' : 'text-[#BD271E]'
                    }`}
                  >
                    {online ? 'Online' : 'Offline'}
                  </span>
                </div>
                <div className="px-3 py-2 space-y-1.5 text-[12px] text-[#535966]">
                  <div className="flex justify-between items-center">
                    <span>n8n Workflow SOAR</span>
                    <span
                      className={
                        health?.n8n
                          ? 'text-[#017D73] font-medium'
                          : 'text-[#BD271E] font-medium'
                      }
                    >
                      {health?.n8n ? 'Aktif' : 'Terputus'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Wazuh Manager API</span>
                    <span
                      className={
                        health?.wazuh_api
                          ? 'text-[#017D73] font-medium'
                          : 'text-[#BD271E] font-medium'
                      }
                    >
                      {health?.wazuh_api ? 'Terhubung' : 'Offline'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>AI Reasoning Engine</span>
                    <span
                      className={
                        health?.gemini
                          ? 'text-[#017D73] font-medium'
                          : 'text-[#BD271E] font-medium'
                      }
                    >
                      {health?.gemini ? 'Siap' : 'Kunci Kosong'}
                    </span>
                  </div>
                </div>
                {onNavigate && (
                  <div className="pt-1.5 px-3 border-t border-[#E1E6EB]">
                    <button
                      onClick={() => {
                        onNavigate('settings');
                        setActiveMenu(null);
                      }}
                      className="w-full text-left py-1 text-[12px] text-[#006BB4] hover:underline font-medium"
                    >
                      Buka Pengaturan &amp; Health &rarr;
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 2. Workspace / Tenant Selector (default) */}
          <div className="relative">
            <button
              onClick={() => toggleMenu('tenant')}
              className={`flex items-center gap-1 text-[13px] text-[#1A1C21] px-2 py-1 rounded transition-colors ${
                activeMenu === 'tenant' ? 'bg-[#E1E6EB]' : 'hover:bg-[#F5F7FA]'
              }`}
              title="Pilih Workspace"
              aria-expanded={activeMenu === 'tenant'}
            >
              <span>default</span>
              <WuiIcon type="arrowDown" size="s" className="text-[#69707D]" />
            </button>

            {/* Tenant Dropdown */}
            {activeMenu === 'tenant' && (
              <div className="absolute right-0 top-full mt-2 w-64 bg-white border border-[#D3DAE6] rounded-[4px] shadow-lg z-50 py-1">
                <div className="px-3 py-1.5 border-b border-[#E1E6EB]">
                  <div className="text-[12px] font-semibold text-[#343741]">
                    Workspace
                  </div>
                </div>
                <div className="py-1">
                  <div className="px-3 py-2 bg-[#F5F7FA] flex items-center justify-between text-[12px]">
                    <div>
                      <div className="font-semibold text-[#1A1C21]">default</div>
                      <div className="text-[11px] text-[#535966]">
                        Global Environment (Aktif)
                      </div>
                    </div>
                    <WuiIcon type="checkInCircleFilled" size="m" className="text-[#017D73]" />
                  </div>
                  <div className="px-3 py-2 text-[12px] text-[#8A94A6] cursor-not-allowed">
                    <div className="font-medium">SOC Lab / Sandbox</div>
                    <div className="text-[11px]">Tersedia pada kluster multi-tenant</div>
                  </div>
                </div>
                <div className="px-3 py-1.5 border-t border-[#E1E6EB] text-[11px] text-[#5A626F]">
                  Mengawasi {stats?.total || 7} endpoint dalam sistem fleet saat ini.
                </div>
              </div>
            )}
          </div>

          {/* User Profile & Role Selector (OuiAvatar style) */}
          <div className="relative">
            <button
              onClick={() => toggleMenu('user')}
              className={`flex items-center gap-1.5 text-[12px] px-1.5 py-1 rounded-[4px] transition-colors ${
                activeMenu === 'user' ? 'bg-[#EBF5FB]' : 'hover:bg-[#F5F7FA]'
              }`}
              title="Profil & Role Pengguna"
              aria-expanded={activeMenu === 'user'}
            >
              <span className="w-6 h-6 rounded-full bg-[#006BB4] text-white text-[11px] font-semibold flex items-center justify-center uppercase shrink-0">
                {(currentUser?.username || 'A').slice(0, 1)}
              </span>
              <span className="font-medium text-[#1A1C21] max-w-[90px] truncate hidden sm:inline">
                {currentUser?.username || 'admin'}
              </span>
              <WuiIcon type="arrowDown" size="xs" className="text-[#535966]" />
            </button>

            {/* User Dropdown */}
            {activeMenu === 'user' && (
              <div className="absolute right-0 top-full mt-2 w-64 bg-white border border-[#D3DAE6] rounded-[4px] shadow-lg z-50 py-1">
                <div className="px-3 py-2 border-b border-[#E1E6EB]">
                  <div className="text-[12px] font-semibold text-[#1A1C21]">
                    {currentUser?.name || currentUser?.username || 'Administrator'}
                  </div>
                  <div className="text-[11px] text-[#5A626F] truncate">
                    {currentUser?.email || 'admin@soar.local'}
                  </div>
                  <div className="mt-1 flex items-center gap-1">
                    <span className="text-[11px] text-[#69707D]">Role:</span>
                    <span className="text-[11px] font-mono font-semibold text-[#1A1C21] uppercase">
                      {currentUser?.role || 'admin'}
                    </span>
                  </div>
                </div>

                <div className="py-1 text-[12px]">
                  {onNavigate && (
                    <button
                      onClick={() => {
                        onNavigate('users');
                        setActiveMenu(null);
                      }}
                      className="w-full flex items-center gap-2 px-3 py-1.5 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                    >
                      <WuiIcon type="usersRolesApp" size="s" className="ouiIcon--mono text-[#535966]" />
                      <span>Kelola Pengguna (RBAC)</span>
                    </button>
                  )}
                  {onNavigate && (
                    <button
                      onClick={() => {
                        onNavigate('api-keys');
                        setActiveMenu(null);
                      }}
                      className="w-full flex items-center gap-2 px-3 py-1.5 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                    >
                      <WuiIcon type="lock" size="s" className="text-[#535966]" />
                      <span>API Keys &amp; 2FA Gate</span>
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={loggingOut}
                    onClick={async () => {
                      try {
                        setLoggingOut(true);
                        const res = await fetch('/api/auth/logout', {
                          method: 'POST',
                          credentials: 'same-origin',
                        });
                        const data = await res.json().catch(() => null);
                        setCurrentUser(null);
                        setActiveMenu(null);
                        if (data && typeof data.logoutUrl === 'string' && data.logoutUrl) {
                          window.location.assign(data.logoutUrl);
                          return;
                        }
                        window.location.reload();
                      } catch {
                        window.location.reload();
                      } finally {
                        setLoggingOut(false);
                      }
                    }}
                    className="w-full flex items-center gap-2 px-3 py-1.5 text-[#BD271E] hover:bg-[#FDF3F2] transition-colors border-t border-[#E1E6EB] disabled:opacity-50 cursor-pointer"
                  >
                    <WuiIcon type="exit" size="s" className="text-[#BD271E]" />
                    <span>{loggingOut ? 'Keluar...' : 'Keluar / Logout'}</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* 3. Action Icons Group */}
          <div className="flex items-center gap-0.5 sm:gap-1 text-[#5A626F]">
            {/* 3a. Help Button */}
            <div className="relative">
              <button
                onClick={() => toggleMenu('help')}
                className={`p-1.5 rounded-[4px] transition-colors ${
                  activeMenu === 'help'
                    ? 'bg-[#E9EDF3] text-[#1A1C21]'
                    : 'hover:bg-[#F5F7FA] text-[#535966]'
                }`}
                title="Bantuan & Dokumentasi"
                aria-label="Bantuan & Dokumentasi"
                aria-expanded={activeMenu === 'help'}
              >
                <WuiIcon type="help" size="m" />
              </button>

              {/* Help Dropdown */}
              {activeMenu === 'help' && (
                <div className="absolute right-0 top-full mt-2 w-64 bg-white border border-[#D3DAE6] rounded-[4px] shadow-lg z-50 py-1">
                  <div className="px-3 py-1.5 border-b border-[#E1E6EB]">
                    <div className="text-[12px] font-semibold text-[#343741]">
                      Bantuan &amp; panduan
                    </div>
                  </div>
                  <div className="py-1 text-[12px]">
                    <a
                      href="https://documentation.wazuh.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-between px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                      onClick={() => setActiveMenu(null)}
                    >
                      <span>Dokumentasi Wazuh</span>
                      <WuiIcon type="popout" size="s" className="text-[#69707D]" />
                    </a>
                    <a
                      href="https://attack.mitre.org"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-between px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                      onClick={() => setActiveMenu(null)}
                    >
                      <span>MITRE ATT&amp;CK Matrix</span>
                      <WuiIcon type="popout" size="s" className="text-[#69707D]" />
                    </a>
                    {onNavigate && (
                      <button
                        onClick={() => {
                          onNavigate('settings');
                          setActiveMenu(null);
                        }}
                        className="w-full text-left px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                      >
                        Konfigurasi &amp; Endpoint Backend
                      </button>
                    )}
                    <button
                      onClick={() => {
                        setAboutOpen(true);
                        setActiveMenu(null);
                      }}
                      className="w-full text-left px-3 py-2 text-[#006BB4] hover:bg-[#F5F7FA] transition-colors border-t border-[#E1E6EB] font-medium"
                    >
                      Tentang SOAR Fleet Monitor
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* 3b. Notifications (Bell) Button */}
            <div className="relative">
              <button
                onClick={() => toggleMenu('notifications')}
                className={`p-1.5 rounded inline-flex items-center relative transition-colors ${
                  activeMenu === 'notifications'
                    ? 'bg-[#E1E6EB] text-[#1A1C21]'
                    : 'hover:bg-[#F5F7FA] text-[#5A626F]'
                }`}
                title="Notifikasi & Alert"
                aria-label="Notifikasi & Alert"
                aria-expanded={activeMenu === 'notifications'}
              >
                <WuiIcon type="bell" size="m" />
                {totalThreats > 0 && (
                  <span className="ml-0.5 px-1 py-0 bg-[#BD271E] text-white text-[11px] font-semibold leading-4 rounded-[3px] tabular-nums">
                    {totalThreats > 99 ? '99+' : totalThreats}
                  </span>
                )}
              </button>

              {/* Notifications Popover */}
              {activeMenu === 'notifications' && (
                <div className="absolute right-0 top-full mt-2 w-80 bg-white border border-[#D3DAE6] rounded shadow-lg z-50 py-1">
                  <div className="px-3 py-2 border-b border-[#E1E6EB] flex items-center justify-between bg-[#FAFBFD]">
                    <div className="text-[12px] font-semibold text-[#1A1C21]">
                      Notifikasi Sistem
                    </div>
                    {totalThreats > 0 && (
                      <button
                        type="button"
                        onClick={() => {
                          onNavigate?.('security-events', {
                            severity: ['CRITICAL', 'HIGH'],
                            tab: 'events',
                            period: 'all',
                            source: 'soar',
                          });
                          setActiveMenu(null);
                        }}
                        className="text-[11px] font-semibold text-[#BD271E] hover:underline transition-colors cursor-pointer"
                        title="Total Critical + High di database SOAR (semua waktu)"
                      >
                        {totalThreats} Kritis/High
                      </button>
                    )}
                  </div>
                  <div className="max-h-72 overflow-y-auto divide-y divide-[#E1E6EB] text-[12px]">
                    {/* Item 1: Threats */}
                    <div
                      className="p-3 hover:bg-[#FAFBFD] cursor-pointer transition-colors group"
                      onClick={() => {
                        onNavigate?.('security-events', {
                          severity: ['CRITICAL', 'HIGH'],
                          tab: 'events',
                          period: 'all',
                          source: 'soar',
                        });
                        setActiveMenu(null);
                      }}
                    >
                      <div className="flex items-start gap-2.5">
                        <WuiIcon type="securityAnalyticsApp" size="m" className="ouiIcon--mono text-[#BD271E] mt-0.5" />
                        <div className="flex-1">
                          <div className="font-semibold text-[#1A1C21] flex items-center justify-between">
                            <span>Alerts Keamanan Kritis</span>
                            <span className="text-[11px] text-[#006BB4] group-hover:underline font-normal">
                              Tinjau Events &rarr;
                            </span>
                          </div>
                          <div className="flex items-center gap-2 mt-1 text-[11px] tabular-nums">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onNavigate?.('security-events', {
                                  severity: ['CRITICAL'],
                                  tab: 'events',
                                  period: 'all',
                                  source: 'soar',
                                });
                                setActiveMenu(null);
                              }}
                              className="font-semibold text-[#BD271E] hover:underline cursor-pointer"
                              title="Filter hanya alert Critical"
                            >
                              {stats?.severity?.CRITICAL || 0} Critical
                            </button>
                            <span className="text-[#98A2B3]">·</span>
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onNavigate?.('security-events', {
                                  severity: ['HIGH'],
                                  tab: 'events',
                                  period: 'all',
                                  source: 'soar',
                                });
                                setActiveMenu(null);
                              }}
                              className="font-semibold text-[#935E00] hover:underline cursor-pointer"
                              title="Filter hanya alert High"
                            >
                              {stats?.severity?.HIGH || 0} High Alerts
                            </button>
                          </div>
                          <div className="text-[11px] text-[#5A626F] mt-1 leading-snug">
                            {totalThreats} Kritis/High (24h) dari{' '}
                            {(stats?.events_all_time ?? stats?.events_total ?? 0).toLocaleString('en-US')} total event di database
                            SOAR. Events memakai periode 7 hari secara default.
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Item 2: Endpoints */}
                    <div
                      className="p-3 hover:bg-[#FAFBFD] cursor-pointer transition-colors"
                      onClick={() => {
                        onNavigate?.('agents');
                        setActiveMenu(null);
                      }}
                    >
                      <div className="flex items-start gap-2.5">
                        <WuiIcon type="spacesApp" size="m" className="ouiIcon--mono text-[#017D73] mt-0.5" />
                        <div>
                          <div className="font-semibold text-[#1A1C21]">
                            {stats?.active || 0} dari {stats?.total || 0} Agent Aktif
                          </div>
                          <div className="text-[11px] text-[#535966] mt-0.5 leading-snug">
                            Semua endpoint Rust ({stats?.rust || 0}) dan Wazuh (
                            {stats?.wazuh || 0}) terpantau live.
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Item 3: SOAR Workflow */}
                    <div className="p-3">
                      <div className="flex items-start gap-2.5">
                        <WuiIcon type="checkInCircleFilled" size="m" className="text-[#006BB4] mt-0.5" />
                        <div>
                          <div className="font-semibold text-[#1A1C21]">
                            Pipeline SOAR n8n Siap
                          </div>
                          <div className="text-[11px] text-[#5A626F] mt-0.5 leading-snug">
                            Playbook respons otomatis (Block Domain &amp; Karantina File)
                            beroperasi normal.
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {onNavigate && (
                    <div className="p-2 border-t border-[#E1E6EB] bg-[#FAFBFD]">
                      <button
                        onClick={() => {
                          onNavigate('security-events', { severity: [], tab: 'events' });
                          setActiveMenu(null);
                        }}
                        className="w-full text-center py-1 text-[12px] font-semibold text-[#006BB4] hover:underline cursor-pointer"
                      >
                        Buka Semua Security Events &rarr;
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* 3c. More (...) Button */}
            <div className="relative">
              <button
                onClick={() => toggleMenu('more')}
                className={`p-1.5 rounded transition-colors ${
                  activeMenu === 'more'
                    ? 'bg-[#E1E6EB] text-[#1A1C21]'
                    : 'hover:bg-[#F5F7FA] text-[#5A626F]'
                }`}
                title="Menu Lainnya"
                aria-label="Menu Lainnya"
                aria-expanded={activeMenu === 'more'}
              >
                <WuiIcon type="boxesVertical" size="m" />
              </button>

              {/* More Dropdown */}
              {activeMenu === 'more' && (
                <div className="absolute right-0 top-full mt-2 w-56 bg-white border border-[#D3DAE6] rounded-[4px] shadow-lg z-50 py-1">
                  <div className="px-3 py-1.5 border-b border-[#E1E6EB]">
                    <div className="text-[12px] font-semibold text-[#343741]">
                      Aksi cepat
                    </div>
                  </div>
                  <div className="py-1 text-[12px]">
                    {onRefresh && (
                      <button
                        onClick={() => {
                          onRefresh();
                          setActiveMenu(null);
                        }}
                        className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                      >
                        <WuiIcon type="refresh" size="s" className="text-[#535966]" />
                        <span>Refresh Data Live</span>
                      </button>
                    )}
                    {onNavigate && (
                      <>
                        <button
                          onClick={() => {
                            onNavigate('agents');
                            setActiveMenu(null);
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                        >
                          <WuiIcon type="spacesApp" size="s" className="ouiIcon--mono text-[#535966]" />
                          <span>Fleet Inventory</span>
                        </button>
                        <button
                          onClick={() => {
                            onNavigate('network-map');
                            setActiveMenu(null);
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                        >
                          <WuiIcon type="graphApp" size="s" className="ouiIcon--mono text-[#535966]" />
                          <span>Network Map</span>
                        </button>
                        <button
                          onClick={() => {
                            onNavigate('integrity-monitoring');
                            setActiveMenu(null);
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                        >
                          <WuiIcon type="sqlApp" size="s" className="ouiIcon--mono text-[#535966]" />
                          <span>Integrity Monitoring (FIM)</span>
                        </button>
                        <button
                          onClick={() => {
                            onNavigate('settings');
                            setActiveMenu(null);
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                        >
                          <WuiIcon type="gear" size="s" className="text-[#535966]" />
                          <span>Pengaturan &amp; Health</span>
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => {
                        setAboutOpen(true);
                        setActiveMenu(null);
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-[#006BB4] hover:bg-[#F5F7FA] transition-colors border-t border-[#E1E6EB] font-medium"
                    >
                      <WuiIcon type="iInCircle" size="s" className="text-[#006BB4]" />
                      <span>Tentang SOAR Monitor</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Wazuh Plugin Navigation Strip (WzMenu style) */}
      {onNavigate && (
        <nav
          aria-label="Wazuh modules navigation"
          className="bg-white border-b border-[#D3DAE6] px-4 flex items-center gap-1 overflow-x-auto select-none"
        >
          {WZ_TOP_NAV.map((item) => {
            const isActive =
              activeView === item.id ||
              (item.id === 'agents' && activeView === 'agent-detail');
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onNavigate(item.id)}
                className={`px-3 py-2 text-[12px] whitespace-nowrap border-b-2 transition-colors cursor-pointer ${
                  isActive
                    ? 'border-[#006BB4] text-[#006BB4] font-semibold'
                    : 'border-transparent text-[#535966] hover:text-[#1A1C21]'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>
      )}

      {/* About System Modal */}
      {aboutOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#1A1C21]/40 p-4">
          <div className="bg-white rounded-[4px] border border-[#D3DAE6] shadow-[0_6px_24px_rgba(0,0,0,0.14)] max-w-lg w-full overflow-hidden relative">
            <div className="flex items-center justify-between px-4 py-3 bg-[#FAFBFD] border-b border-[#D3DAE6]">
              <div>
                <h3 className="text-[14px] font-semibold text-[#1A1C21]">
                  SOAR Fleet Monitor
                </h3>
                <p className="text-[11px] text-[#535966]">
                  Sistem Keamanan &amp; Respons Otomatis Terdistribusi
                </p>
              </div>
              <button
                onClick={() => setAboutOpen(false)}
                className="p-1 rounded-[4px] text-[#535966] hover:bg-[#E9EDF3] hover:text-[#1A1C21] transition-colors"
                aria-label="Tutup"
              >
                <WuiIcon type="cross" size="m" />
              </button>
            </div>

            <div className="p-4 space-y-3 text-[12px] text-[#1A1C21]">
              <div className="bg-[#FAFBFD] border border-[#D3DAE6] rounded-[4px] p-3 space-y-2">
                <div className="flex justify-between">
                  <span className="text-[#535966]">Endpoint Agent:</span>
                  <span className="font-mono font-medium">Rust (soar-agent, ~4.1 MB)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#535966]">Detection Engine:</span>
                  <span className="font-mono font-medium">Wazuh Manager 4.14.8 (SIEM / FIM)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#535966]">Automation Core:</span>
                  <span className="font-mono font-medium">n8n 2.42.5 Workflow Engine</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#535966]">Backend Monitor:</span>
                  <span className="font-mono font-medium">Python 3.12 (SQLite WAL Mode)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#535966]">Dashboard UI:</span>
                  <span className="font-mono font-medium">Next.js 16 (Wazuh OUI Theme)</span>
                </div>
              </div>

              <div className="text-[12px] text-[#535966] leading-relaxed">
                Dirancang untuk pemantauan hingga 100 workstation dengan konsumsi memori
                rendah, analisis threat intelligence multi-sumber otomatis, serta aksi
                respons karantina file dan isolasi domain secara instan.
              </div>
            </div>

            <div className="px-4 py-3 bg-[#FAFBFD] border-t border-[#E9EDF3] flex justify-end">
              <button
                onClick={() => setAboutOpen(false)}
                className="px-4 py-1.5 bg-[#006BB4] hover:bg-[#00538C] text-white text-[12px] font-medium rounded-[4px] transition-colors"
              >
                Tutup
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
});
