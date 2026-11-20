'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { WuiIcon, type WuiIconType } from '../wui/WuiIcon';
import { WuiCodeBlock } from '../wui/WuiPrimitives';

export type InstallerTarget = 'linux' | 'windows' | 'macos' | 'universal';
export type InstallerMode = 'install' | 'update';
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

function buildUniversalCommands(
  managerHost: string,
): Record<UniversalTarget, { label: string; code: string; verify: string; note: string }> {
  const host = managerHost || 'WAZUH_MANAGER_IP';
  return {
    debian: {
      label: 'Debian / Ubuntu / Mint (APT)',
      code: `curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list && sudo apt-get update && sudo WAZUH_MANAGER="${host}" apt-get install -y wazuh-agent && sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent`,
      verify: 'sudo systemctl status wazuh-agent',
      note: `Terhubung langsung ke Wazuh Manager ${host} (:1514 / :1515).`,
    },
    rhel: {
      label: 'RHEL / Rocky / Alma / Fedora (RPM)',
      code: `sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && sudo bash -c 'cat > /etc/yum.repos.d/wazuh.repo <<EOF\n[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1\nEOF' && sudo WAZUH_MANAGER="${host}" yum install -y wazuh-agent && sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent`,
      verify: 'sudo systemctl status wazuh-agent',
      note: 'Untuk CentOS, Rocky Linux, AlmaLinux, dan Fedora.',
    },
    'macos-pkg': {
      label: 'macOS Official Wazuh PKG (arm64 / Intel)',
      code: `ARCH=$(uname -m | sed 's/x86_64/intel64/') && curl -so wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.8-1.\${ARCH}.pkg" && echo "WAZUH_MANAGER='${host}'" | sudo tee /tmp/wazuh_envs && sudo installer -pkg wazuh-agent.pkg -target / && sudo /Library/Ossec/bin/wazuh-control start`,
      verify: 'sudo /Library/Ossec/bin/wazuh-control status',
      note: 'Alternatif Wazuh Agent resmi untuk macOS.',
    },
    'windows-msi': {
      label: 'Windows Official Wazuh MSI',
      code: `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi -OutFile $env:TEMP\\wazuh-agent.msi; msiexec.exe /i $env:TEMP\\wazuh-agent.msi /q WAZUH_MANAGER="${host}"; NET START WazuhSvc`,
      verify: 'Get-Service WazuhSvc',
      note: 'Alternatif Wazuh Agent resmi untuk Windows Server dan workstation.',
    },
    freebsd: {
      label: 'FreeBSD / Solaris / AIX / Source',
      code: `pkg install -y wazuh-agent && sudo sed -i '' 's/MANAGER_IP/${host}/' /var/ossec/etc/ossec.conf && sudo service wazuh-agent onestart`,
      verify: 'sudo service wazuh-agent status',
      note: 'Untuk BSD/Unix lain atau kompilasi agent-rs dengan cargo build --release.',
    },
  };
}

function buildUniversalUpdateCommands(): Record<
  UniversalTarget,
  { label: string; code: string; verify: string; note: string }
> {
  return {
    debian: {
      label: 'Debian / Ubuntu / Mint (APT)',
      code: `sudo apt-get update && sudo apt-get --only-upgrade install -y wazuh-agent && sudo systemctl daemon-reload && sudo systemctl restart wazuh-agent`,
      verify: 'sudo systemctl status wazuh-agent',
      note: 'Memperbarui paket wazuh-agent ke versi repositori terbaru dan me-restart service.',
    },
    rhel: {
      label: 'RHEL / Rocky / Alma / Fedora (RPM)',
      code: `sudo yum check-update; sudo yum upgrade -y wazuh-agent && sudo systemctl daemon-reload && sudo systemctl restart wazuh-agent`,
      verify: 'sudo systemctl status wazuh-agent',
      note: 'Memperbarui paket RPM wazuh-agent ke versi repositori terbaru.',
    },
    'macos-pkg': {
      label: 'macOS Official Wazuh PKG (arm64 / Intel)',
      code: `ARCH=$(uname -m | sed 's/x86_64/intel64/') && curl -so wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.8-1.\${ARCH}.pkg" && sudo installer -pkg wazuh-agent.pkg -target / && sudo /Library/Ossec/bin/wazuh-control restart`,
      verify: 'sudo /Library/Ossec/bin/wazuh-control status',
      note: 'Memperbarui paket PKG Wazuh Agent resmi di macOS.',
    },
    'windows-msi': {
      label: 'Windows Official Wazuh MSI',
      code: `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi -OutFile $env:TEMP\\wazuh-agent.msi; msiexec.exe /i $env:TEMP\\wazuh-agent.msi /qn REINSTALL=ALL REINSTALLMODE=vomus; Restart-Service WazuhSvc`,
      verify: 'Get-Service WazuhSvc',
      note: 'Memperbarui instalasi MSI Wazuh Agent resmi di Windows.',
    },
    freebsd: {
      label: 'FreeBSD / Solaris / AIX / Source',
      code: `pkg upgrade -y wazuh-agent && sudo service wazuh-agent restart`,
      verify: 'sudo service wazuh-agent status',
      note: 'Memperbarui paket wazuh-agent pada FreeBSD.',
    },
  };
}

function StepNumber({ num }: { num: number }) {
  return (
    <div className="w-6 h-6 rounded-full bg-[#006BB4] text-white text-[12px] font-semibold tabular-nums flex items-center justify-center shrink-0">
      {num}
    </div>
  );
}

export function AgentInstallerPanel({ installerOrigin }: AgentInstallerPanelProps) {
  const [mode, setMode] = useState<InstallerMode>('install');
  const [targetOs, setTargetOs] = useState<InstallerTarget>('linux');
  const [universalTarget, setUniversalTarget] = useState<UniversalTarget>('debian');
  const [managerHost, setManagerHost] = useState<string>('WAZUH_MANAGER_IP');

  useEffect(() => {
    fetch('/api/config/public', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.wazuhManagerHost) setManagerHost(String(d.wazuhManagerHost));
      })
      .catch(() => {});
  }, []);

  const UNIVERSAL_COMMANDS = useMemo(() => buildUniversalCommands(managerHost), [managerHost]);
  const UNIVERSAL_UPDATE_COMMANDS = useMemo(() => buildUniversalUpdateCommands(), []);

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
      verify: 'sudo launchctl print system/io.soar.agent',
      scriptLabel: 'install-soar-agent-macos.sh',
      binHref: '/api/installer/download/soar-agent-macos',
      binLabel: 'soar-agent (macOS)',
    },
  };

  const updateCommandsByOs: Record<
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
      code: `curl -sSL ${installerOrigin}/api/enroll/script?os=linux&action=update | sudo bash`,
      helper: 'Jalankan sebagai root atau sudo. Memperbarui biner soar-agent di /usr/local/bin/soar-agent dan me-restart service tanpa mengubah token atau meminta persetujuan ulang.',
      verify: 'sudo systemctl status soar-agent',
      scriptLabel: 'update-soar-agent.sh',
      binHref: '/api/installer/download/soar-agent',
      binLabel: 'soar-agent (Linux x86_64)',
    },
    windows: {
      code: `irm ${installerOrigin}/api/enroll/script?os=windows&action=update | iex`,
      helper: 'Buka PowerShell sebagai Administrator. Menghentikan sementara Scheduled Task, mengganti soar-agent.exe di Program Files, dan menjalankan kembali task tanpa menyentuh token.',
      verify: 'Get-ScheduledTask -TaskName "SOAR Agent"',
      scriptLabel: 'update-soar-agent.ps1',
      binHref: '/api/installer/download/soar-agent.exe',
      binLabel: 'soar-agent.exe (Windows x64)',
    },
    macos: {
      code: `curl -sSL ${installerOrigin}/api/enroll/script?os=macos&action=update | sudo bash`,
      helper: 'Jalankan di Terminal dengan sudo. Memperbarui biner LaunchDaemon dan memuat ulang service tanpa mengubah token pendaftaran.',
      verify: 'sudo launchctl print system/io.soar.agent',
      scriptLabel: 'update-soar-agent-macos.sh',
      binHref: '/api/installer/download/soar-agent-macos',
      binLabel: 'soar-agent (macOS)',
    },
  };

  const activeUniversalCommands = mode === 'update' ? UNIVERSAL_UPDATE_COMMANDS : UNIVERSAL_COMMANDS;
  const activeCommandsByOs = mode === 'update' ? updateCommandsByOs : commandsByOs;

  const serverDisplay =
    targetOs === 'universal'
      ? `${managerHost} (TCP :1514 / :1515)`
      : installerOrigin.replace(/^https?:\/\//, '');

  const activeVerify =
    targetOs === 'universal'
      ? activeUniversalCommands[universalTarget].verify
      : activeCommandsByOs[targetOs].verify;

  return (
    <section className="bg-white border border-[#D3DAE6] rounded-[4px] p-6 space-y-6">
      {/* Mode Switcher Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#D3DAE6] pb-4">
        <div className="flex items-center gap-1.5 p-0.5 bg-[#F4F5F7] border border-[#D3DAE6] rounded-[4px]">
          <button
            type="button"
            onClick={() => setMode('install')}
            className={`h-7 px-3 text-[12px] font-medium rounded-[3px] transition-all cursor-pointer flex items-center gap-1.5 ${
              mode === 'install'
                ? 'bg-[#006BB4] text-white shadow-xs'
                : 'text-[#535966] hover:text-[#1A1C21] hover:bg-white/60'
            }`}
          >
            <span>Instalasi Baru (New Agent)</span>
          </button>
          <button
            type="button"
            onClick={() => setMode('update')}
            className={`h-7 px-3 text-[12px] font-medium rounded-[3px] transition-all cursor-pointer flex items-center gap-1.5 ${
              mode === 'update'
                ? 'bg-[#006BB4] text-white shadow-xs'
                : 'text-[#535966] hover:text-[#1A1C21] hover:bg-white/60'
            }`}
          >
            <WuiIcon type="refresh" size="s" />
            <span>Pembaruan Agen (Update Agent)</span>
          </button>
        </div>
        <div className="text-[12px] text-[#535966]">
          {mode === 'install'
            ? 'Mendaftarkan endpoint baru ke cluster SOAR'
            : 'Perbarui biner endpoint aktif tanpa menghapus token atau approval ulang'}
        </div>
      </div>

      {mode === 'update' && (
        <div className="p-3.5 bg-[#F4F9FD] border border-[#006BB4]/30 rounded-[4px] text-[12px] text-[#1A1C21] flex items-start gap-2.5">
          <WuiIcon type="check" size="m" className="text-[#006BB4] mt-0.5 shrink-0" />
          <div className="space-y-0.5">
            <div className="font-semibold text-[#006BB4]">Pembaruan In-Place Cepat (One-Line Command)</div>
            <div className="text-[#535966] leading-relaxed">
              Perintah pembaruan akan mengunduh biner <span className="font-mono text-[#1A1C21]">soar-agent</span> versi terbaru, memvalidasi integritas checksum SHA-256, dan me-restart background service. Konfigurasi token pendaftaran (<span className="font-mono text-[#1A1C21]">fleet.token</span>) dan Agent ID di endpoint tetap terjaga aman tanpa memerlukan persetujuan (approval) ulang dari Admin.
            </div>
          </div>
        </div>
      )}

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
                {mode === 'install'
                  ? 'Pilih platform target endpoint yang akan dihubungkan ke SOAR & Wazuh Manager.'
                  : 'Pilih sistem operasi endpoint yang ingin diperbarui biner agennya.'}
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
                  {Object.entries(activeUniversalCommands).map(([key, item]) => (
                    <option key={key} value={key}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </div>

        {/* Step 2: Server & Policy */}
        <div className="flex gap-4">
          <div className="flex flex-col items-center">
            <StepNumber num={2} />
            <div className="w-px flex-1 bg-[#D3DAE6] mt-2" />
          </div>
          <div className="flex-1 min-w-0 pb-2 space-y-2.5">
            <div>
              <h2 className="text-[14px] font-semibold text-[#1A1C21]">
                {mode === 'install'
                  ? 'Server address & enrollment policy'
                  : 'Server address & token policy'}
              </h2>
              <p className="text-[12px] text-[#535966] mt-0.5">
                {mode === 'install'
                  ? 'Alamat server tujuan yang disisipkan ke skrip instalasi.'
                  : 'Alamat server tujuan untuk pengunduhan biner dan verifikasi checksum.'}
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
                <div className="text-[#535966] font-medium mb-1">
                  {mode === 'install' ? 'Otorisasi pendaftaran' : 'Kebijakan pendaftaran'}
                </div>
                <div className="h-8 px-3 bg-[#FAFBFD] border border-[#D3DAE6] rounded-[4px] flex items-center text-[#1A1C21]">
                  {targetOs === 'universal'
                    ? mode === 'install'
                      ? 'Wazuh Manager Authd (:1515)'
                      : 'Wazuh Repository Upgrade'
                    : mode === 'install'
                      ? 'Persetujuan Admin (Pending Approvals)'
                      : 'Pertahankan Token & ID Lama (Tanpa Approval)'}
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
                {mode === 'install'
                  ? 'Remember to run the command as administrator'
                  : 'Run update command as administrator'}
              </h2>
              <p className="text-[12px] text-[#535966] mt-0.5">
                {mode === 'install'
                  ? 'Salin dan jalankan perintah berikut pada perangkat target untuk memasang dan mendaftarkan agent.'
                  : 'Salin dan jalankan perintah berikut pada perangkat target untuk memperbarui biner dan me-restart service.'}
              </p>
            </div>

            {targetOs !== 'universal' ? (
              <div className="space-y-2">
                <WuiCodeBlock
                  code={activeCommandsByOs[targetOs].code}
                  helperText={activeCommandsByOs[targetOs].helper}
                />
                <div className="flex flex-wrap items-center gap-4 text-[12px] pt-1">
                  <span className="text-[#535966]">Unduhan langsung:</span>
                  <a
                    href={
                      mode === 'update'
                        ? `/api/enroll/script?os=${targetOs}&action=update`
                        : `/api/enroll/script?os=${targetOs}`
                    }
                    className="text-[#006BB4] hover:underline font-mono text-[11.5px] inline-flex items-center gap-1"
                  >
                    <WuiIcon type="download" size="s" />
                    <span>{activeCommandsByOs[targetOs].scriptLabel}</span>
                  </a>
                  <a
                    href={activeCommandsByOs[targetOs].binHref}
                    className="text-[#006BB4] hover:underline font-mono text-[11.5px] inline-flex items-center gap-1"
                  >
                    <WuiIcon type="download" size="s" />
                    <span>{activeCommandsByOs[targetOs].binLabel}</span>
                  </a>
                </div>
              </div>
            ) : (
              <WuiCodeBlock
                code={activeUniversalCommands[universalTarget].code}
                helperText={activeUniversalCommands[universalTarget].note}
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
                {mode === 'install'
                  ? 'Approve and verify agent connection'
                  : 'Verify updated agent connection'}
              </h2>
              <p className="text-[12px] text-[#535966] mt-0.5">
                {targetOs === 'universal'
                  ? mode === 'install'
                    ? 'Setelah instalasi selesai, pastikan service Wazuh Agent berjalan dan host tampil aktif di menu Agents.'
                    : 'Setelah pembaruan selesai, pastikan service Wazuh Agent berjalan aktif.'
                  : mode === 'install'
                    ? 'Saat skrip menunggu persetujuan, buka menu Deploy agent -> Pending approvals di dashboard admin (soar.raviarnan.dev) lalu klik Approve. Setelah disetujui, cek status service dengan perintah:'
                    : 'Pembaruan biner diterapkan langsung pada background service. Pastikan service agent berjalan aktif dengan perintah berikut (endpoint akan otomatis mengirim heartbeat versi baru ke server):'}
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
