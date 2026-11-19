'use client';

import React, { useEffect, useState } from 'react';
import { WuiIcon } from '@/components/wui/WuiIcon';
import { WazuhLogo } from '@/components/wazuh/WazuhLogo';
import { AgentInstallerPanel } from '@/components/wazuh/AgentInstallerPanel';

export default function PublicAgentInstallPage() {
  const [origin, setOrigin] = useState('https://soar-agent.example.com');
  const [dashboardUrl, setDashboardUrl] = useState('/');

  useEffect(() => {
    const fallbackOrigin =
      typeof window !== 'undefined' && window.location.origin
        ? window.location.origin
        : 'https://soar-agent.example.com';
    fetch('/api/config/public', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        setOrigin(d?.publicEnrollUrl ? String(d.publicEnrollUrl) : fallbackOrigin);
        if (d?.publicSoarUrl) setDashboardUrl(String(d.publicSoarUrl));
      })
      .catch(() => {
        setOrigin(fallbackOrigin);
      });
  }, []);

  return (
    <div className="min-h-screen bg-[#FAFBFD] text-[#1A1C21] flex flex-col">
      <header className="h-12 bg-white border-b border-[#D3DAE6] flex items-center justify-between px-4 sticky top-0 z-40">
        <div className="flex items-center gap-3 min-w-0">
          <WazuhLogo className="h-[18px] text-[#1A1C21] shrink-0" width={88} height={21} />
          <div className="flex items-center gap-1.5 text-[13px] text-[#5A626F] truncate">
            <span className="text-[#8A94A6]">/</span>
            <span>Agents</span>
            <span className="text-[#8A94A6]">/</span>
            <span className="text-[#1A1C21] font-medium">Deploy new agent</span>
          </div>
        </div>

        <a
          href={dashboardUrl}
          className="text-[12px] font-medium text-[#006BB4] hover:underline inline-flex items-center gap-1 shrink-0"
        >
          <span>Dashboard Admin</span>
          <WuiIcon type="popout" size="s" />
        </a>
      </header>

      <main className="flex-1 w-full max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-5">
        <div>
          <h1 className="text-[22px] font-semibold text-[#1A1C21] leading-tight">
            Deploy new agent
          </h1>
          <p className="text-[13px] text-[#535966] mt-1">
            Ikuti langkah berikut untuk memasang dan mendaftarkan endpoint agent SOAR (Linux, Windows, macOS, atau Wazuh Agent).
          </p>
        </div>

        <AgentInstallerPanel installerOrigin={origin} />
      </main>
    </div>
  );
}
