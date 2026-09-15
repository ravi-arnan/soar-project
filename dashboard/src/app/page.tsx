'use client';

import React, { useMemo, useState } from 'react';
import { WazuhHeader } from '@/components/wazuh/WazuhHeader';
import { WazuhSidebar } from '@/components/wazuh/WazuhSidebar';
import { ModulesHub } from '@/components/wazuh/ModulesHub';
import { SecurityEventsDashboard } from '@/components/wazuh/SecurityEventsDashboard';
import { AgentsManagement } from '@/components/wazuh/AgentsManagement';
import { AgentDetailView } from '@/components/wazuh/AgentDetailView';
import { FimDashboard } from '@/components/wazuh/FimDashboard';
import { VulnerabilitiesDashboard } from '@/components/wazuh/VulnerabilitiesDashboard';
import { SettingsView } from '@/components/wazuh/SettingsView';
import { useFleet } from '@/lib/fleet';

export default function Home() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [currentView, setCurrentView] = useState<string>('modules');
  const [selectedAgentId, setSelectedAgentId] = useState<string>('004');

  // Data live dari scripts/fleet-monitor.py (poll 5s).
  const { snapshot, events, online, error, refresh } = useFleet();

  const { stats, agents, health } = snapshot;
  const selectedAgent = useMemo(
    () => agents.find((a) => a.id === selectedAgentId),
    [agents, selectedAgentId]
  );

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
    if (currentView === 'vulnerabilities') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Vulnerabilities' },
      ];
    }
    if (currentView === 'agents') {
      return [{ label: 'Agents', onClick: () => setCurrentView('agents') }];
    }
    if (currentView === 'settings') {
      return [
        { label: 'Modules', onClick: () => setCurrentView('modules') },
        { label: 'Settings' },
      ];
    }
    if (currentView === 'agent-detail') {
      return [
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

  return (
    <div className="min-h-screen bg-[#F5F7FA] text-[#1A1C21] flex flex-col font-sans antialiased">
      {/* Top Wazuh Global Header */}
      <WazuhHeader
        breadcrumbs={getBreadcrumbs()}
        onToggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)}
        online={online}
      />

      {/* Slide-out Sidebar Drawer */}
      <WazuhSidebar
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
        activeView={currentView}
        onSelectView={(viewId) => setCurrentView(viewId)}
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
            onNavigate={(modKey) => {
              if (modKey === 'agents') setCurrentView('agents');
              else if (modKey === 'security-events') setCurrentView('security-events');
              else if (modKey === 'integrity-monitoring') setCurrentView('integrity-monitoring');
              else if (modKey === 'vulnerabilities') setCurrentView('vulnerabilities');
              else setCurrentView('security-events');
            }}
          />
        )}

        {currentView === 'security-events' && (
          <SecurityEventsDashboard
            events={events}
            stats={stats}
            onSelectAgent={handleSelectAgent}
            onRefresh={refresh}
          />
        )}

        {currentView === 'agents' && (
          <AgentsManagement agents={agents} onSelectAgent={handleSelectAgent} />
        )}

        {currentView === 'agent-detail' && (
          <AgentDetailView
            agentId={selectedAgentId}
            agent={selectedAgent}
            events={events}
            onNavigateTab={(tab) => {
              if (tab === 'Security events') setCurrentView('security-events');
              if (tab === 'Integrity monitoring') setCurrentView('integrity-monitoring');
              if (tab === 'Vulnerabilities') setCurrentView('vulnerabilities');
            }}
          />
        )}

        {currentView === 'integrity-monitoring' && <FimDashboard events={events} />}

        {currentView === 'vulnerabilities' && <VulnerabilitiesDashboard />}

        {currentView === 'settings' && (
          <SettingsView
            health={health}
            stats={stats}
            generatedAt={snapshot.generated_at}
            online={online}
          />
        )}
      </main>
    </div>
  );
}
