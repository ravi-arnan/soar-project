'use client';

import React, { useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import dynamic from 'next/dynamic';
import { AuthProvider, LoginGate, useAuth } from '@/components/AuthContext';
import { WazuhHeader } from '@/components/wazuh/WazuhHeader';
import { WazuhSidebar } from '@/components/wazuh/WazuhSidebar';
import { ModulesHub } from '@/components/wazuh/ModulesHub';
import type { SettingsTabId } from '@/components/wazuh/SettingsView';
import { useFleet } from '@/lib/fleet';
import type { HistorySource, PeriodPreset } from '@/lib/fleet';

function ViewSkeleton() {
  return (
    <div className="p-8 text-center text-[#535966] text-sm bg-white border border-[#D3DAE6] rounded-[4px]">
      Memuat modul...
    </div>
  );
}

const SecurityEventsDashboard = dynamic(
  () => import('@/components/wazuh/SecurityEventsDashboard').then((m) => m.SecurityEventsDashboard),
  { loading: () => <ViewSkeleton /> }
);
const AgentsManagement = dynamic(
  () => import('@/components/wazuh/AgentsManagement').then((m) => m.AgentsManagement),
  { loading: () => <ViewSkeleton /> }
);
const AgentDetailView = dynamic(
  () => import('@/components/wazuh/AgentDetailView').then((m) => m.AgentDetailView),
  { loading: () => <ViewSkeleton /> }
);
const FimDashboard = dynamic(
  () => import('@/components/wazuh/FimDashboard').then((m) => m.FimDashboard),
  { loading: () => <ViewSkeleton /> }
);
const ThreatIntelView = dynamic(
  () => import('@/components/wazuh/ThreatIntelView').then((m) => m.ThreatIntelView),
  { loading: () => <ViewSkeleton /> }
);
const MitreAttackView = dynamic(
  () => import('@/components/wazuh/MitreAttackView').then((m) => m.MitreAttackView),
  { loading: () => <ViewSkeleton /> }
);
const NetworkMapView = dynamic(
  () => import('@/components/wazuh/NetworkMapView').then((m) => m.NetworkMapView),
  { loading: () => <ViewSkeleton /> }
);
const SettingsView = dynamic(
  () => import('@/components/wazuh/SettingsView').then((m) => m.SettingsView),
  { loading: () => <ViewSkeleton /> }
);
const ApiKeysView = dynamic(
  () => import('@/components/wazuh/ApiKeysView').then((m) => m.ApiKeysView),
  { loading: () => <ViewSkeleton /> }
);
const UserManagementView = dynamic(
  () => import('@/components/wazuh/UserManagementView').then((m) => m.UserManagementView),
  { loading: () => <ViewSkeleton /> }
);
const AgentDeploymentView = dynamic(
  () => import('@/components/wazuh/AgentDeploymentView').then((m) => m.AgentDeploymentView),
  { loading: () => <ViewSkeleton /> }
);

export default function Home() {
  return (
    <AuthProvider>
      <DashboardShell />
    </AuthProvider>
  );
}

function DashboardShell() {
  const { authenticated, loading: authLoading, role } = useAuth();
  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#FAFBFD] flex items-center justify-center text-[13px] text-[#535966]">
        Memeriksa sesi autentikasi...
      </div>
    );
  }
  if (!authenticated || !role) {
    return <LoginGate />;
  }
  return <AuthenticatedDashboard userRole={role} />;
}

const VALID_VIEWS = new Set([
  'modules',
  'security-events',
  'integrity-monitoring',
  'threat-intel',
  'mitre',
  'network-map',
  'agents',
  'agent-detail',
  'deploy-agent',
  'settings',
  'api-keys',
  'users',
]);

function readUrlParam(key: string): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return new URLSearchParams(window.location.search).get(key);
  } catch {
    return null;
  }
}

function AuthenticatedDashboard({ userRole }: { userRole: 'admin' | 'analyst' | 'viewer' }) {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [currentView, setCurrentView] = useState<string>(() => {
    const v = readUrlParam('view');
    return v && VALID_VIEWS.has(v) ? v : 'modules';
  });
  const [selectedAgentId, setSelectedAgentId] = useState<string>(() => readUrlParam('agent') || '004');
  const [eventsAgentFilter, setEventsAgentFilter] = useState<string | undefined>(
    () => readUrlParam('events_agent') || undefined
  );
  const [eventsSeverityFilter, setEventsSeverityFilter] = useState<string[] | undefined>(() => {
    const raw = readUrlParam('severity');
    if (!raw) return undefined;
    const list = raw
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);
    return list.length > 0 ? list : undefined;
  });
  const [eventsActiveTab, setEventsActiveTab] = useState<'dashboard' | 'events' | undefined>(() => {
    const t = readUrlParam('tab');
    return t === 'dashboard' || t === 'events' ? t : undefined;
  });
  const [eventsPeriod, setEventsPeriod] = useState<PeriodPreset | undefined>(() => {
    const p = readUrlParam('period');
    return p === '24h' || p === '7d' || p === '30d' || p === '90d' || p === 'all' ? p : undefined;
  });
  const [eventsSource, setEventsSource] = useState<HistorySource | undefined>(() => {
    const s = readUrlParam('source');
    return s === 'all' || s === 'soar' || s === 'wazuh' ? s : undefined;
  });
  const [settingsInitialTab, setSettingsInitialTab] = useState<SettingsTabId>(() => {
    const st = readUrlParam('stab');
    return st === 'general' ||
      st === 'keys' ||
      st === 'dynamic-config' ||
      st === 'command-history' ||
      st === 'audit-trail'
      ? st
      : 'general';
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams();
    if (currentView && currentView !== 'modules') params.set('view', currentView);
    if (currentView === 'agent-detail' && selectedAgentId) params.set('agent', selectedAgentId);
    if (currentView === 'security-events') {
      if (eventsAgentFilter) params.set('events_agent', eventsAgentFilter);
      if (eventsSeverityFilter && eventsSeverityFilter.length > 0) {
        params.set('severity', eventsSeverityFilter.join(','));
      }
      if (eventsActiveTab) params.set('tab', eventsActiveTab);
      if (eventsPeriod) params.set('period', eventsPeriod);
      if (eventsSource && eventsSource !== 'all') params.set('source', eventsSource);
    }
    if (currentView === 'settings' && settingsInitialTab !== 'general') {
      params.set('stab', settingsInitialTab);
    }
    const qs = params.toString();
    const nextUrl = `${window.location.pathname}${qs ? `?${qs}` : ''}`;
    if (`${window.location.pathname}${window.location.search}` !== nextUrl) {
      window.history.replaceState(null, '', nextUrl);
    }
  }, [
    currentView,
    selectedAgentId,
    eventsAgentFilter,
    eventsSeverityFilter,
    eventsActiveTab,
    eventsPeriod,
    eventsSource,
    settingsInitialTab,
  ]);

  // Baca preferensi refreshMs via useSyncExternalStore (deterministik SSR=5000, bebas hydration mismatch).
  const [refreshOverride, setRefreshOverride] = useState<number | null>(null);
  const storedRefreshMs = useSyncExternalStore(
    (cb) => {
      if (typeof window === 'undefined') return () => {};
      window.addEventListener('storage', cb);
      return () => window.removeEventListener('storage', cb);
    },
    () => {
      try {
        const saved = Number(localStorage.getItem('soar:refreshMs'));
        return saved && saved >= 2000 ? saved : 5000;
      } catch {
        return 5000;
      }
    },
    () => 5000
  );
  const refreshMs = refreshOverride ?? storedRefreshMs;
  const updateRefreshMs = (ms: number) => {
    setRefreshOverride(ms);
    try {
      localStorage.setItem('soar:refreshMs', String(ms));
    } catch {}
  };

  // Data live dari scripts/fleet-monitor.py (poll sesuai preferensi).
  const { snapshot, online, error, refresh } = useFleet(refreshMs);

  const { stats, agents, health } = snapshot;
  // Fallback ke agent pertama bila id terpilih tak ada (misal default awal).
  const selectedAgent = useMemo(
    () =>
      agents.find((a) => a.id === selectedAgentId) ||
      agents.find((a) => a.id === selectedAgentId.replace(/^0+/, '')) ||
      agents[0],
    [agents, selectedAgentId]
  );
  const effectiveAgentId = selectedAgent?.id || selectedAgentId;

  // Breadcrumbs construction
  const getBreadcrumbs = () => {
    if (currentView === 'modules') {
      return [{ label: 'Modules', onClick: () => setCurrentView('modules') }];
    }
    if (currentView === 'security-events') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Security events' },
      ];
    }
    if (currentView === 'integrity-monitoring') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Integrity monitoring' },
      ];
    }
    if (currentView === 'threat-intel') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Threat Intel' },
      ];
    }
    if (currentView === 'mitre') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'MITRE ATT&CK' },
      ];
    }
    if (currentView === 'network-map') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Network map' },
      ];
    }
    if (currentView === 'agents') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Agents' },
      ];
    }
    if (currentView === 'settings') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Settings' },
      ];
    }
    if (currentView === 'api-keys') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'API Keys & Agent Access' },
      ];
    }
    if (currentView === 'users') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'User Management' },
      ];
    }
    if (currentView === 'agent-deployment') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Agents', onClick: () => setCurrentView('agents') },
        { label: 'Agent Deployment & Approval' },
      ];
    }
    if (currentView === 'agent-detail') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Agents', onClick: () => setCurrentView('agents') },
        { label: selectedAgent?.name || `Agent ${selectedAgentId}` },
      ];
    }
    return [{ label: 'Modules', onClick: () => setCurrentView('modules') }];
  };

  const handleSelectAgent = (agentId: string) => {
    setSelectedAgentId(agentId);
    setCurrentView('agent-detail');
  };

  const handleNavigate = (
    viewId: string,
    options?: {
      severity?: string[];
      agentId?: string;
      tab?: 'dashboard' | 'events';
      period?: PeriodPreset;
      source?: HistorySource;
    }
  ) => {
    // Navigasi baru ke Security events selalu reset filter lama, kecuali
    // pemanggil eksplisit mengirim severity/agent/tab.
    if (viewId === 'security-events') {
      setEventsSeverityFilter(options?.severity);
      setEventsAgentFilter(options?.agentId);
      setEventsActiveTab(options?.tab);
      setEventsPeriod(options?.period);
      setEventsSource(options?.source);
    }
    if (viewId === 'settings') {
      setSettingsInitialTab('general');
    }
    setCurrentView(viewId);
  };

  return (
    <div className="min-h-screen bg-[#F5F7FA] text-[#1A1C21] flex flex-col font-sans antialiased">
      {/* Top Wazuh Global Header */}
      <WazuhHeader
        breadcrumbs={getBreadcrumbs()}
        onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)}
        online={online}
        stats={stats}
        health={health}
        activeView={currentView}
        onNavigate={handleNavigate}
        onRefresh={refresh}
      />

      {/* Slide-out Sidebar Drawer */}
      <WazuhSidebar
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
        activeView={currentView}
        onSelectView={handleNavigate}
        agentCount={stats.total}
        health={health}
      />

      {/* Main Content Area */}
      <main className="flex-1 p-4 lg:p-6 max-w-[1600px] w-full mx-auto">
        {!online && error && (
          <div className="mb-4 border border-[#F5C2C0] bg-[#FDF3F2] text-[#BD271E] text-[12px] rounded px-3 py-2">
            Backend fleet tidak terjangkau ({error}). Menampilkan data terakhir yang sempat terbaca.
          </div>
        )}

        {currentView === 'modules' && (
          <ModulesHub
            stats={stats}
            agents={agents}
            health={health}
            onNavigate={(modKey, opts) => {
              if (modKey === 'agents') setCurrentView('agents');
              else if (modKey === 'scan-on-demand') {
                // Langsung ke detail agent Rust pertama supaya kartu scan on-demand terlihat.
                const rust = agents.find((a) => a.type === 'rust') || agents[0];
                if (rust) setSelectedAgentId(rust.id);
                setCurrentView('agent-detail');
              }
              else if (modKey === 'playbook-runs') setCurrentView('mitre');
              else if (modKey === 'ai-triage') setCurrentView('threat-intel');
              else if (modKey === 'security-events') handleNavigate('security-events', opts);
              else if (modKey === 'integrity-monitoring') setCurrentView('integrity-monitoring');
              else if (modKey === 'threat-intel') setCurrentView('threat-intel');
              else if (modKey === 'mitre') setCurrentView('mitre');
              else if (modKey === 'network-map') setCurrentView('network-map');
              else if (modKey === 'users') setCurrentView('users');
              else if (modKey === 'api-keys') setCurrentView('api-keys');
              else if (modKey === 'settings') setCurrentView('settings');
              else handleNavigate('security-events', opts);
            }}
          />
        )}

        {currentView === 'security-events' && (
          <SecurityEventsDashboard
            onSelectAgent={handleSelectAgent}
            onOpenAgents={() => setCurrentView('agents')}
            onRefresh={refresh}
            initialAgentId={eventsAgentFilter}
            initialSeverity={eventsSeverityFilter}
            initialTab={eventsActiveTab}
            initialPeriod={eventsPeriod}
            initialSource={eventsSource}
          />
        )}

        {currentView === 'agents' && (
          <AgentsManagement
            agents={agents}
            onSelectAgent={handleSelectAgent}
            onOpenSettings={() => setCurrentView('settings')}
            onOpenDeployment={() => setCurrentView('agent-deployment')}
            onRefresh={refresh}
          />
        )}

        {currentView === 'agent-deployment' && (
          <AgentDeploymentView
            onBackToAgents={() => setCurrentView('agents')}
            userRole={userRole}
          />
        )}

        {currentView === 'agent-detail' && (
          <AgentDetailView
            agentId={effectiveAgentId}
            agent={selectedAgent}
            onNavigateTab={(tab, agentId) => {
              if (tab === 'Security events') {
                setEventsAgentFilter(agentId);
                setEventsSeverityFilter(undefined);
                setEventsActiveTab(undefined);
                setEventsPeriod(undefined);
                setEventsSource(undefined);
                setCurrentView('security-events');
              } else if (tab === 'Integrity monitoring') {
                setCurrentView('integrity-monitoring');
              } else if (tab === 'Threat Intel') {
                setCurrentView('threat-intel');
              }
            }}
          />
        )}

        {currentView === 'integrity-monitoring' && <FimDashboard />}

        {currentView === 'mitre' && (
          <MitreAttackView
            onSelectTechnique={() =>
              handleNavigate('security-events', { tab: 'events', period: '30d', source: 'all' })
            }
          />
        )}

        {currentView === 'network-map' && (
          <NetworkMapView agents={agents} health={health} onSelectAgent={handleSelectAgent} />
        )}

        {currentView === 'threat-intel' && (
          <ThreatIntelView
            onOpenAiSettings={() => {
              setSettingsInitialTab('dynamic-config');
              setCurrentView('settings');
            }}
          />
        )}

        {currentView === 'users' && userRole === 'admin' && <UserManagementView />}

        {currentView === 'api-keys' && userRole === 'admin' && <ApiKeysView />}

        {currentView === 'settings' && (
          <SettingsView
            health={health}
            stats={stats}
            generatedAt={snapshot.generated_at}
            online={online}
            refreshMs={refreshMs}
            onRefreshMsChange={updateRefreshMs}
            initialTab={settingsInitialTab}
            userRole={userRole}
          />
        )}
      </main>
    </div>
  );
}
