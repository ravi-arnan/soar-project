'use client';

import React, { useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import { WazuhHeader } from '@/components/wazuh/WazuhHeader';
import { WazuhSidebar } from '@/components/wazuh/WazuhSidebar';
import { ModulesHub } from '@/components/wazuh/ModulesHub';
import { useFleet } from '@/lib/fleet';
import type { HistorySource, PeriodPreset } from '@/lib/fleet';

function ViewSkeleton() {
  return (
    <div className="p-8 text-center text-[#5A626F] text-sm animate-pulse bg-white border border-[#D3DAE6] rounded">
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

export default function Home() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [currentView, setCurrentView] = useState<string>('modules');
  const [selectedAgentId, setSelectedAgentId] = useState<string>('004');
  const [eventsAgentFilter, setEventsAgentFilter] = useState<string | undefined>(undefined);
  const [eventsSeverityFilter, setEventsSeverityFilter] = useState<string[] | undefined>(undefined);
  const [eventsActiveTab, setEventsActiveTab] = useState<'dashboard' | 'events' | undefined>(undefined);
  const [eventsPeriod, setEventsPeriod] = useState<PeriodPreset | undefined>(undefined);
  const [eventsSource, setEventsSource] = useState<HistorySource | undefined>(undefined);

  const [refreshMs, setRefreshMs] = useState(() => {
    try {
      return Number(localStorage.getItem('soar:refreshMs')) || 5000;
    } catch {
      return 5000;
    }
  });
  const updateRefreshMs = (ms: number) => {
    setRefreshMs(ms);
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
            onNavigate={(modKey) => {
              if (modKey === 'agents') setCurrentView('agents');
              else if (modKey === 'scan-on-demand') {
                // Langsung ke detail agent Rust pertama supaya kartu scan on-demand terlihat.
                const rust = agents.find((a) => a.type === 'rust') || agents[0];
                if (rust) setSelectedAgentId(rust.id);
                setCurrentView('agent-detail');
              }
              else if (modKey === 'security-events') handleNavigate('security-events');
              else if (modKey === 'integrity-monitoring') setCurrentView('integrity-monitoring');
              else if (modKey === 'threat-intel') setCurrentView('threat-intel');
              else if (modKey === 'mitre') setCurrentView('mitre');
              else if (modKey === 'network-map') setCurrentView('network-map');
              else if (modKey === 'settings') setCurrentView('settings');
              else handleNavigate('security-events');
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
            onRefresh={refresh}
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

        {currentView === 'mitre' && <MitreAttackView />}

        {currentView === 'network-map' && (
          <NetworkMapView agents={agents} onSelectAgent={handleSelectAgent} />
        )}

        {currentView === 'threat-intel' && <ThreatIntelView />}

        {currentView === 'settings' && (
          <SettingsView
            health={health}
            stats={stats}
            generatedAt={snapshot.generated_at}
            online={online}
            refreshMs={refreshMs}
            onRefreshMsChange={updateRefreshMs}
          />
        )}
      </main>
    </div>
  );
}
