'use client';

import React, { useState } from 'react';
import { WuiIcon, type WuiIconType } from '../wui/WuiIcon';
import { WuiCodeBlock } from '../wui/WuiPrimitives';

export type InstallerTarget = 'linux' | 'windows' | 'macos' | 'universal';
type UniversalTarget = 'debian' | 'rhel' | 'macos-pkg' | 'windows-msi' | 'freebsd';

interface AgentInstallerPanelProps {
  installerOrigin: string;
}

const OS_CARDS: Array<{
  id: InstallerTarget;
  label: string;
  sub: string;
  icon: WuiIconType;
}> = [
  { id: 'linux', label: 'Linux', sub: 'DEB, RPM, Arch, Alpine, NixOS', icon: 'osLinux' },
  { id: 'windows', label: 'Windows', sub: 'Windows 10/11 & Server', icon: 'osWindows' },
  { id: 'macos', label: 'macOS', sub: 'Apple Silicon & Intel', icon: 'osMac' },
  { id: 'universal', label: 'Wazuh / OS Lain', sub: 'Official Agent 4.14 (BSD, PKG, MSI)', icon: 'node' },
];

const UNIVERSAL_COMMANDS: Record<
  UniversalTarget,
  { label: string; code: string; verify: string; note: string }
> = {
  debian: {
    label: 'Debian / Ubuntu / Mint (APT)',
    code: `curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list && sudo apt-get update && sudo WAZUH_MANAGER="100.73.91.17" apt-get install -y wazuh-agent && sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent`,
    verify: 'sudo systemctl status wazuh-agent',
    note: 'Terhubung langsung ke Wazuh Manager 100.73.91.17 (:1514 / :1515).',
  },
  rhel: {
    label: 'RHEL / Rocky / Alma / Fedora (RPM)',
    code: `sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && sudo bash -c 'cat > /etc/yum.repos.d/wazuh.repo <<EOF\n[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1\nEOF' && sudo WAZUH_MANAGER="100.73.91.17" yum install -y wazuh-agent && sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent`,
    verify: 'sudo systemctl status wazuh-agent',
    note: 'Untuk CentOS, Rocky Linux, AlmaLinux, dan Fedora.',
  },
  'macos-pkg': {
    label: 'macOS Official Wazuh PKG (arm64 / Intel)',
    code: `ARCH=$(uname -m | sed 's/x86_64/intel64/') && curl -so wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.8-1.\${ARCH}.pkg" && echo "WAZUH_MANAGER='100.73.91.17'" | sudo tee /tmp/wazuh_envs && sudo installer -pkg wazuh-agent.pkg -target / && sudo /Library/Ossec/bin/wazuh-control start`,
    verify: 'sudo /Library/Ossec/bin/wazuh-control status',
    note: 'Alternatif Wazuh Agent resmi untuk macOS.',
  },
  'windows-msi': {
    label: 'Windows Official Wazuh MSI',
    code: `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi -OutFile $env:TEMP\\wazuh-agent.msi; msiexec.exe /i $env:TEMP\\wazuh-agent.msi /q WAZUH_MANAGER="100.73.91.17"; NET START WazuhSvc`,
    verify: 'Get-Service WazuhSvc',
    note: 'Alternatif Wazuh Agent resmi untuk Windows Server dan workstation.',
  },
  freebsd: {
    label: 'FreeBSD / Solaris / AIX / Source',
    code: `pkg install -y wazuh-agent && sudo sed -i '' 's/MANAGER_IP/100.73.91.17/' /var/ossec/etc/ossec.conf && sudo service wazuh-agent onestart`,
    verify: 'sudo service wazuh-agent status',
    note: 'Untuk BSD/Unix lain atau kompilasi agent-rs dengan cargo build --release.',
  },
};

function StepNumber({ num }: { num: number }) {
  return (
    <div className="w-6 h-6 rounded-full bg-[#006BB4] text-white text-[12px] font-semibold tabular-nums flex items-center justify-center shrink-0">
      {num}
    </div>
  );
}

/**
 * Wizard pemasangan agent bergaya Wazuh UI (OuiSteps vertikal dalam 1 panel flat):
 * 1. Pilih sistem operasi
 * 2. Alamat server & mode enrollment
 * 3. Jalankan perintah instalasi
 * 4. Verifikasi & approval
 */
export function AgentInstallerPanel({ installerOrigin }: AgentInstallerPanelProps) {
  const [targetOs, setTargetOs] = useState<InstallerTarget>('linux');
  const [universalTarget, setUniversalTarget] = useState<UniversalTarget>('debian');

  const commandsByOs: Record<
    Exclude<InstallerTarget, 'universal'>,
    {
      code: string;
      helper: string;
      verify: string;
      scriptLabel: string;
      binHref: string;
      binLabel: string;
    }
  > = {
    linux: {
      code: `curl -sSL ${installerOrigin}/api/enroll/script?os=linux | sudo bash`,
      helper: 'Jalankan sebagai root atau sudo. Otomatis memasang unit systemd/OpenRC dan menunggu approval Admin.',
      verify: 'sudo systemctl status soar-agent',
      scriptLabel: 'install-soar-agent.sh',
      binHref: '/api/installer/download/soar-agent',
      binLabel: 'soar-agent (Linux x86_64)',
    },
    windows: {
      code: `irm ${installerOrigin}/api/enroll/script?os=windows | iex`,
      helper: 'Buka PowerShell sebagai Administrator. Otomatis mengunduh binary, mengunci token, dan mendaftarkan Scheduled Task SYSTEM.',
      verify: 'Get-ScheduledTask -TaskName "SOAR Agent"',
      scriptLabel: 'install-soar-agent.ps1',
      binHref: '/api/installer/download/soar-agent.exe',
      binLabel: 'soar-agent.exe (Windows x64)',
    },
    macos: {
      code: `curl -sSL ${installerOrigin}/api/enroll/script?os=macos | sudo bash`,
      helper: 'Jalankan di Terminal dengan sudo. Mendukung Apple Silicon (arm64) dan Intel (x86_64) melalui LaunchDaemon launchd.',
      verify: 'sudo launchctl print system/dev.raviarnan.soar-agent',
      scriptLabel: 'install-soar-agent-macos.sh',
      binHref: '/api/installer/download/soar-agent-macos',
      binLabel: 'soar-agent (macOS)',
    },
  };

  const serverDisplay =
    targetOs === 'universal'
      ? '100.73.91.17 (TCP :1514 / :1515)'
      : installerOrigin.replace(/^https?:\/\//, '');

  const activeVerify =
    targetOs === 'universal'
      ? UNIVERSAL_COMMANDS[universalTarget].verify
      : commandsByOs[targetOs].verify;

  return (
    <section className="bg-white border border-[#D3DAE6] rounded-[4px] p-6">
      <div className="space-y-6">
        {/* Step 1: Select OS */}
        <div className="flex gap-4">
          <div className="flex flex-col items-center">
            <StepNumber num={1} />
            <div className="w-px flex-1 bg-[#D3DAE6] mt-2" />
          </div>
          <div className="flex-1 min-w-0 pb-2 space-y-3">
            <div>
              <h2 className="text-[14px] font-semibold text-[#1A1C21]">
                Select the operating system
              </h2>
              <p className="text-[12px] text-[#535966] mt-0.5">
                Pilih platform target endpoint yang akan dihubungkan ke SOAR &amp; Wazuh Manager.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {OS_CARDS.map((card) => {
                const selected = targetOs === card.id;
                return (
                  <button
                    key={card.id}
                    type="button"
                    onClick={() => setTargetOs(card.id)}
                    className={`text-left p-3 rounded-[4px] border transition-colors cursor-pointer flex items-start gap-2.5 ${
                      selected
                        ? 'border-[#006BB4] bg-[#F4F9FD] ring-1 ring-[#006BB4]'
                        : 'border-[#D3DAE6] bg-white hover:border-[#98A2B3]'
                    }`}
                  >
                    <input
                      type="radio"
                      name="soar-agent-os"
                      checked={selected}
                      onChange={() => setTargetOs(card.id)}
                      className="mt-1 accent-[#006BB4] pointer-events-none"
                      tabIndex={-1}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5 text-[13px] font-semibold text-[#1A1C21]">
                        <WuiIcon type={card.icon} size="s" />
                        <span>{card.label}</span>
                      </div>
                      <div className="text-[11px] text-[#535966] mt-0.5 leading-snug">
                        {card.sub}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            {targetOs === 'universal' && (
              <div className="pt-1 max-w-md">
                <label className="block text-[12px] font-medium text-[#1A1C21] mb-1">
                  Distribusi / Paket Wazuh Official
                </label>
                <select
                  value={universalTarget}
                  onChange={(e) => setUniversalTarget(e.target.value as UniversalTarget)}
                  className="w-full h-8 px-2.5 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px] text-[#1A1C21] outline-none focus:border-[#006BB4]"
                >
                  {Object.entries(UNIVERSAL_COMMANDS).map(([key, item]) => (
                    <option key={key} value={key}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </div>

        {/* Step 2: Server & Enrollment */}
        <div className="flex gap-4">
          <div className="flex flex-col items-center">
            <StepNumber num={2} />
            <div className="w-px flex-1 bg-[#D3DAE6] mt-2" />
          </div>
          <div className="flex-1 min-w-0 pb-2 space-y-2.5">
            <div>
              <h2 className="text-[14px] font-semibold text-[#1A1C21]">
                Server address &amp; enrollment policy
              </h2>
              <p className="text-[12px] text-[#535966] mt-0.5">
                Alamat server tujuan yang disisipkan ke skrip instalasi.
              </p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-2xl text-[12px]">
              <div>
                <div className="text-[#535966] font-medium mb-1">Server address</div>
                <div className="h-8 px-3 bg-[#FAFBFD] border border-[#D3DAE6] rounded-[4px] flex items-center font-mono text-[#1A1C21]">
                  {serverDisplay}
                </div>
              </div>
              <div>
                <div className="text-[#535966] font-medium mb-1">Otorisasi pendaftaran</div>
                <div className="h-8 px-3 bg-[#FAFBFD] border border-[#D3DAE6] rounded-[4px] flex items-center text-[#1A1C21]">
                  {targetOs === 'universal'
                    ? 'Wazuh Manager Authd (:1515)'
                    : 'Persetujuan Admin (Pending Approvals)'}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Step 3: Run Command */}
        <div className="flex gap-4">
          <div className="flex flex-col items-center">
            <StepNumber num={3} />
            <div className="w-px flex-1 bg-[#D3DAE6] mt-2" />
          </div>
          <div className="flex-1 min-w-0 pb-2 space-y-2.5">
            <div>
              <h2 className="text-[14px] font-semibold text-[#1A1C21]">
                Remember to run the command as administrator
              </h2>
              <p className="text-[12px] text-[#535966] mt-0.5">
                Salin dan jalankan perintah berikut pada perangkat target untuk memasang dan mendaftarkan agent.
              </p>
            </div>

            {targetOs !== 'universal' ? (
              <div className="space-y-2">
                <WuiCodeBlock
                  code={commandsByOs[targetOs].code}
                  helperText={commandsByOs[targetOs].helper}
                />
                <div className="flex flex-wrap items-center gap-4 text-[12px] pt-1">
                  <span className="text-[#535966]">Unduhan langsung:</span>
                  <a
                    href={`/api/enroll/script?os=${targetOs}`}
                    className="text-[#006BB4] hover:underline font-mono text-[11.5px] inline-flex items-center gap-1"
                  >
                    <WuiIcon type="download" size="s" />
                    <span>{commandsByOs[targetOs].scriptLabel}</span>
                  </a>
                  <a
                    href={commandsByOs[targetOs].binHref}
                    className="text-[#006BB4] hover:underline font-mono text-[11.5px] inline-flex items-center gap-1"
                  >
                    <WuiIcon type="download" size="s" />
                    <span>{commandsByOs[targetOs].binLabel}</span>
                  </a>
                </div>
              </div>
            ) : (
              <WuiCodeBlock
                code={UNIVERSAL_COMMANDS[universalTarget].code}
                helperText={UNIVERSAL_COMMANDS[universalTarget].note}
              />
            )}
          </div>
        </div>

        {/* Step 4: Verify & Approve */}
        <div className="flex gap-4">
          <div className="flex flex-col items-center">
            <StepNumber num={4} />
          </div>
          <div className="flex-1 min-w-0 space-y-2.5">
            <div>
              <h2 className="text-[14px] font-semibold text-[#1A1C21]">
                Approve and verify agent connection
              </h2>
              <p className="text-[12px] text-[#535966] mt-0.5">
                {targetOs === 'universal'
                  ? 'Setelah instalasi selesai, pastikan service Wazuh Agent berjalan dan host tampil aktif di menu Agents.'
                  : 'Saat skrip menunggu persetujuan, buka menu Deploy agent -> Pending approvals di dashboard admin (soar.raviarnan.dev) lalu klik Approve. Setelah disetujui, cek status service dengan perintah:'}
              </p>
            </div>
            <div className="max-w-xl">
              <WuiCodeBlock code={activeVerify} />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
