'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Menu,
  ChevronDown,
  Bell,
  HelpCircle,
  MoreVertical,
  ExternalLink,
  RefreshCw,
  ShieldAlert,
  Server,
  CheckCircle2,
  Settings,
  Network,
  FileCheck2,
  Info,
  X,
} from 'lucide-react';
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

export const WazuhHeader = React.memo(function WazuhHeader({
  breadcrumbs,
  onToggleSidebar,
  online = true,
  stats,
  health,
  onNavigate,
  onRefresh,
}: WazuhHeaderProps) {
  const [activeMenu, setActiveMenu] = useState<
    'api' | 'tenant' | 'help' | 'notifications' | 'more' | null
  >(null);
  const [aboutOpen, setAboutOpen] = useState(false);
  const menuContainerRef = useRef<HTMLDivElement>(null);

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

  const toggleMenu = (menu: 'api' | 'tenant' | 'help' | 'notifications' | 'more') => {
    setActiveMenu((prev) => (prev === menu ? null : menu));
  };

  return (
    <>
      <header className="h-12 bg-white border-b border-[#D3DAE6] flex items-center justify-between px-4 sticky top-0 z-40 select-none">
        {/* Left side: Hamburger, Logo, Breadcrumbs */}
        <div className="flex items-center gap-3">
          <button
            onClick={onToggleSidebar}
            className="p-1.5 rounded hover:bg-[#F0F4F8] text-[#1A1C21] transition-colors"
            title="Toggle navigation"
            aria-label="Toggle navigation"
          >
            <Menu className="w-5 h-5 text-[#1A1C21]" />
          </button>

          <div
            className="flex items-center gap-1 cursor-pointer"
            onClick={() => breadcrumbs[0]?.onClick?.()}
          >
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
          {/* 1. API Status Badge Button */}
          <div className="relative">
            <button
              onClick={() => toggleMenu('api')}
              className={`flex items-center gap-1.5 text-[12px] px-2 py-0.5 rounded border transition-colors ${
                activeMenu === 'api'
                  ? 'bg-[#E1E6EB] border-[#006BB4] text-[#1A1C21]'
                  : 'bg-[#F5F7FA] border-[#D3DAE6] text-[#5A626F] hover:bg-[#EAEFF5]'
              }`}
              title={online ? 'Fleet API terhubung' : 'Fleet API tidak terjangkau'}
              aria-expanded={activeMenu === 'api'}
            >
              <span
                className={`w-2 h-2 rounded-full ${online ? 'bg-[#00A389]' : 'bg-[#BD271E]'}`}
              ></span>
              <span className="font-semibold text-[#1A1C21]">API</span>
            </button>

            {/* API Popover */}
            {activeMenu === 'api' && (
              <div className="absolute right-0 top-full mt-2 w-64 bg-white border border-[#D3DAE6] rounded shadow-lg z-50 py-2">
                <div className="px-3 py-1.5 border-b border-[#E1E6EB] flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase text-[#5A626F]">
                    Koneksi Backend
                  </span>
                  <span
                    className={`text-[11px] font-medium px-1.5 py-0.5 rounded ${
                      online
                        ? 'bg-[#E6F6F4] text-[#00A389]'
                        : 'bg-[#FDF3F2] text-[#BD271E]'
                    }`}
                  >
                    {online ? 'Online' : 'Offline'}
                  </span>
                </div>
                <div className="px-3 py-2 space-y-1.5 text-[12px] text-[#5A626F]">
                  <div className="flex justify-between items-center">
                    <span>n8n Workflow SOAR</span>
                    <span
                      className={
                        health?.n8n
                          ? 'text-[#00A389] font-medium'
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
                          ? 'text-[#00A389] font-medium'
                          : 'text-[#BD271E] font-medium'
                      }
                    >
                      {health?.wazuh_api ? 'Terhubung' : 'Offline'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Gemini AI Engine</span>
                    <span
                      className={
                        health?.gemini
                          ? 'text-[#00A389] font-medium'
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
              <ChevronDown className="w-3.5 h-3.5 text-[#5A626F]" />
            </button>

            {/* Tenant Dropdown */}
            {activeMenu === 'tenant' && (
              <div className="absolute right-0 top-full mt-2 w-64 bg-white border border-[#D3DAE6] rounded shadow-lg z-50 py-1">
                <div className="px-3 py-1.5 border-b border-[#E1E6EB]">
                  <div className="text-[11px] font-semibold uppercase text-[#5A626F]">
                    Workspace / Ruang Kerja
                  </div>
                </div>
                <div className="py-1">
                  <div className="px-3 py-2 bg-[#F0F4F8] flex items-center justify-between text-[12px]">
                    <div>
                      <div className="font-semibold text-[#1A1C21]">default</div>
                      <div className="text-[11px] text-[#5A626F]">
                        Global Environment (Aktif)
                      </div>
                    </div>
                    <span className="text-[#00A389] font-bold text-sm">✓</span>
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

          {/* 3. Action Icons Group */}
          <div className="flex items-center gap-0.5 sm:gap-1 text-[#5A626F]">
            {/* 3a. Help Button */}
            <div className="relative">
              <button
                onClick={() => toggleMenu('help')}
                className={`p-1.5 rounded transition-colors ${
                  activeMenu === 'help'
                    ? 'bg-[#E1E6EB] text-[#1A1C21]'
                    : 'hover:bg-[#F5F7FA] text-[#5A626F]'
                }`}
                title="Bantuan & Dokumentasi"
                aria-label="Bantuan & Dokumentasi"
                aria-expanded={activeMenu === 'help'}
              >
                <HelpCircle className="w-4 h-4" />
              </button>

              {/* Help Dropdown */}
              {activeMenu === 'help' && (
                <div className="absolute right-0 top-full mt-2 w-64 bg-white border border-[#D3DAE6] rounded shadow-lg z-50 py-1">
                  <div className="px-3 py-1.5 border-b border-[#E1E6EB]">
                    <div className="text-[11px] font-semibold uppercase text-[#5A626F]">
                      Bantuan &amp; Panduan
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
                      <ExternalLink className="w-3.5 h-3.5 text-[#8A94A6]" />
                    </a>
                    <a
                      href="https://attack.mitre.org"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-between px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                      onClick={() => setActiveMenu(null)}
                    >
                      <span>MITRE ATT&amp;CK Matrix</span>
                      <ExternalLink className="w-3.5 h-3.5 text-[#8A94A6]" />
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
                className={`p-1.5 rounded relative transition-colors ${
                  activeMenu === 'notifications'
                    ? 'bg-[#E1E6EB] text-[#1A1C21]'
                    : 'hover:bg-[#F5F7FA] text-[#5A626F]'
                }`}
                title="Notifikasi & Alert"
                aria-label="Notifikasi & Alert"
                aria-expanded={activeMenu === 'notifications'}
              >
                <Bell className="w-4 h-4" />
                {totalThreats > 0 && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-[#BD271E] rounded-full ring-2 ring-white"></span>
                )}
              </button>

              {/* Notifications Popover */}
              {activeMenu === 'notifications' && (
                <div className="absolute right-0 top-full mt-2 w-80 bg-white border border-[#D3DAE6] rounded shadow-lg z-50 py-1">
                  <div className="px-3 py-2 border-b border-[#E1E6EB] flex items-center justify-between bg-[#F8FAFC]">
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
                        className="text-[10px] font-bold bg-[#BD271E] text-white px-2 py-0.5 rounded-full hover:bg-[#9E1F18] transition-colors cursor-pointer"
                        title="Total Critical + High di database SOAR (semua waktu)"
                      >
                        {totalThreats} Kritis/High
                      </button>
                    )}
                  </div>
                  <div className="max-h-72 overflow-y-auto divide-y divide-[#E1E6EB] text-[12px]">
                    {/* Item 1: Threats */}
                    <div
                      className="p-3 hover:bg-[#F8FAFC] cursor-pointer transition-colors group"
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
                        <ShieldAlert className="w-4 h-4 text-[#BD271E] mt-0.5 shrink-0" />
                        <div className="flex-1">
                          <div className="font-semibold text-[#1A1C21] flex items-center justify-between">
                            <span>Alerts Keamanan Kritis</span>
                            <span className="text-[10px] text-[#006BB4] group-hover:underline font-normal">
                              Tinjau Events &rarr;
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5 mt-1">
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
                              className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-semibold bg-[#FDE8E8] text-[#BD271E] hover:bg-[#FBD5D5] transition-colors cursor-pointer"
                              title="Filter hanya alert Critical"
                            >
                              {stats?.severity?.CRITICAL || 0} Critical
                            </button>
                            <span className="text-[#8A94A6]">/</span>
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
                              className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-semibold bg-[#FEF3C7] text-[#B45309] hover:bg-[#FDE68A] transition-colors cursor-pointer"
                              title="Filter hanya alert High"
                            >
                              {stats?.severity?.HIGH || 0} High Alerts
                            </button>
                          </div>
                          <div className="text-[11px] text-[#5A626F] mt-1 leading-snug">
                            {totalThreats} Kritis/High dari{' '}
                            {stats?.events_total?.toLocaleString('en-US') || 0} event di database
                            SOAR (semua waktu). Events memakai periode 7 hari secara default.
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Item 2: Endpoints */}
                    <div
                      className="p-3 hover:bg-[#F8FAFC] cursor-pointer transition-colors"
                      onClick={() => {
                        onNavigate?.('agents');
                        setActiveMenu(null);
                      }}
                    >
                      <div className="flex items-start gap-2.5">
                        <Server className="w-4 h-4 text-[#00A389] mt-0.5 shrink-0" />
                        <div>
                          <div className="font-semibold text-[#1A1C21]">
                            {stats?.active || 0} dari {stats?.total || 0} Agent Aktif
                          </div>
                          <div className="text-[11px] text-[#5A626F] mt-0.5 leading-snug">
                            Semua endpoint Rust ({stats?.rust || 0}) dan Wazuh (
                            {stats?.wazuh || 0}) terpantau live.
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Item 3: SOAR Workflow */}
                    <div className="p-3">
                      <div className="flex items-start gap-2.5">
                        <CheckCircle2 className="w-4 h-4 text-[#006BB4] mt-0.5 shrink-0" />
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
                    <div className="p-2 border-t border-[#E1E6EB] bg-[#F8FAFC]">
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
                <MoreVertical className="w-4 h-4" />
              </button>

              {/* More Dropdown */}
              {activeMenu === 'more' && (
                <div className="absolute right-0 top-full mt-2 w-56 bg-white border border-[#D3DAE6] rounded shadow-lg z-50 py-1">
                  <div className="px-3 py-1.5 border-b border-[#E1E6EB]">
                    <div className="text-[11px] font-semibold uppercase text-[#5A626F]">
                      Aksi Cepat
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
                        <RefreshCw className="w-3.5 h-3.5 text-[#5A626F]" />
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
                          <Server className="w-3.5 h-3.5 text-[#5A626F]" />
                          <span>Fleet Inventory</span>
                        </button>
                        <button
                          onClick={() => {
                            onNavigate('network-map');
                            setActiveMenu(null);
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                        >
                          <Network className="w-3.5 h-3.5 text-[#5A626F]" />
                          <span>Network Map</span>
                        </button>
                        <button
                          onClick={() => {
                            onNavigate('integrity-monitoring');
                            setActiveMenu(null);
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                        >
                          <FileCheck2 className="w-3.5 h-3.5 text-[#5A626F]" />
                          <span>Integrity Monitoring (FIM)</span>
                        </button>
                        <button
                          onClick={() => {
                            onNavigate('settings');
                            setActiveMenu(null);
                          }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-[#1A1C21] hover:bg-[#F5F7FA] transition-colors"
                        >
                          <Settings className="w-3.5 h-3.5 text-[#5A626F]" />
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
                      <Info className="w-3.5 h-3.5 text-[#006BB4]" />
                      <span>Tentang SOAR Monitor</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* About System Modal */}
      {aboutOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
          <div className="bg-white rounded border border-[#D3DAE6] shadow-2xl max-w-lg w-full p-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-[#E1E6EB]">
              <div>
                <h3 className="text-base font-semibold text-[#1A1C21]">
                  SOAR Fleet Monitor
                </h3>
                <p className="text-[12px] text-[#5A626F]">
                  Sistem Keamanan &amp; Respons Otomatis Terdistribusi
                </p>
              </div>
              <button
                onClick={() => setAboutOpen(false)}
                className="p-1 rounded text-[#5A626F] hover:bg-[#F5F7FA] hover:text-[#1A1C21] transition-colors"
                aria-label="Tutup"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="py-4 space-y-3 text-[13px] text-[#1A1C21]">
              <div className="bg-[#F8FAFC] border border-[#E1E6EB] rounded p-3 space-y-2">
                <div className="flex justify-between">
                  <span className="text-[#5A626F]">Endpoint Agent:</span>
                  <span className="font-medium">Rust (soar-agent, ~5.2 MB)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#5A626F]">Detection Engine:</span>
                  <span className="font-medium">Wazuh Manager 4.9 (SIEM / FIM)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#5A626F]">Automation Core:</span>
                  <span className="font-medium">n8n Workflow Engine</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#5A626F]">Backend Monitor:</span>
                  <span className="font-medium">Python 3.12 (SQLite WAL Mode)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#5A626F]">Dashboard:</span>
                  <span className="font-medium">Next.js 16 (React 19 + Tailwind CSS)</span>
                </div>
              </div>

              <div className="text-[12px] text-[#5A626F] leading-relaxed">
                Dirancang untuk pemantauan hingga 100 workstation dengan konsumsi memori
                rendah, analisis threat intelligence VirusTotal &amp; OTX otomatis, serta aksi
                respons karantina file dan isolasi domain secara instan.
              </div>
            </div>

            <div className="pt-3 border-t border-[#E1E6EB] flex justify-end">
              <button
                onClick={() => setAboutOpen(false)}
                className="px-4 py-1.5 bg-[#006BB4] hover:bg-[#005590] text-white text-[12px] font-medium rounded transition-colors"
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
