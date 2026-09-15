'use client';

import React from 'react';
import {
  ShieldAlert,
  FileCheck2,
  Cloud,
  Layers,
  Terminal,
  FileSearch,
  Sliders,
  Activity,
  CheckCircle2,
  BookOpen,
  ShieldCheck,
  Bug,
  Box,
  Database,
  Container,
  Grid,
  CreditCard,
  Building2,
  Lock,
  FileText,
  HeartPulse,
} from 'lucide-react';

import type { FleetStats } from '@/lib/fleet';

interface ModulesHubProps {
  onNavigate: (moduleKey: string) => void;
  /** Ringkasan fleet dari /api/fleet (live). */
  stats: FleetStats;
}

export function ModulesHub({ onNavigate, stats }: ModulesHubProps) {
  const sections = [
    {
      title: 'SECURITY INFORMATION MANAGEMENT',
      modules: [
        {
          id: 'security-events',
          title: 'Security events',
          description:
            'Browse through your security alerts, identifying issues and threats in your environment.',
          icon: ShieldAlert,
        },
        {
          id: 'integrity-monitoring',
          title: 'Integrity monitoring',
          description:
            'Alerts related to file changes, including permissions, content, ownership and attributes.',
          icon: FileCheck2,
        },
        {
          id: 'amazon-aws',
          title: 'Amazon AWS',
          description:
            'Security events related to your Amazon AWS services, collected directly via AWS API.',
          icon: Cloud,
          badge: 'aws',
        },
        {
          id: 'office-365',
          title: 'Office 365',
          description: 'Security events related to your Office 365 services.',
          icon: Layers,
        },
        {
          id: 'gcp',
          title: 'Google Cloud Platform',
          description:
            'Security events related to your Google Cloud Platform services, collected directly via GCP API.',
          icon: Terminal,
        },
        {
          id: 'github',
          title: 'GitHub',
          description: 'Monitoring events from audit logs of your GitHub organizations.',
          icon: FileSearch,
        },
      ],
    },
    {
      title: 'AUDITING AND POLICY MONITORING',
      modules: [
        {
          id: 'policy-monitoring',
          title: 'Policy monitoring',
          description:
            'Verify that your systems are configured according to your security policies baseline.',
          icon: Sliders,
        },
        {
          id: 'system-auditing',
          title: 'System auditing',
          description:
            'Audit users behavior, monitoring command execution and alerting on access to critical files.',
          icon: Activity,
        },
        {
          id: 'openscap',
          title: 'OpenSCAP',
          description:
            'Configuration assessment and automation of compliance monitoring using SCAP checks.',
          icon: CheckCircle2,
        },
        {
          id: 'cis-cat',
          title: 'CIS-CAT',
          description:
            'Configuration assessment using Center of Internet Security scanner and SCAP checks.',
          icon: BookOpen,
        },
        {
          id: 'sca',
          title: 'Security configuration assessment',
          description: 'Scan your assets as part of a configuration assessment audit.',
          icon: ShieldCheck,
        },
      ],
    },
    {
      title: 'THREAT DETECTION AND RESPONSE',
      modules: [
        {
          id: 'vulnerabilities',
          title: 'Vulnerabilities',
          description:
            'Discover what applications in your environment are affected by well-known vulnerabilities.',
          icon: Bug,
        },
        {
          id: 'virustotal',
          title: 'VirusTotal',
          description:
            'Alerts resulting from VirusTotal analysis of suspicious files via an integration with their API.',
          icon: Box,
        },
        {
          id: 'osquery',
          title: 'Osquery',
          description:
            'Osquery can be used to expose an operating system as a high-performance relational database.',
          icon: Database,
        },
        {
          id: 'docker-listener',
          title: 'Docker listener',
          description:
            'Monitor and collect the activity from Docker containers such as creation, running, starting, stopping or pausing events.',
          icon: Container,
        },
        {
          id: 'mitre',
          title: 'MITRE ATT&CK',
          description:
            'Security events from the knowledge base of adversary tactics and techniques based on real-world observations',
          icon: Grid,
        },
      ],
    },
    {
      title: 'REGULATORY COMPLIANCE',
      modules: [
        {
          id: 'pci-dss',
          title: 'PCI DSS',
          description:
            'Global security standard for entities that process, store or transmit payment cardholder data.',
          icon: CreditCard,
        },
        {
          id: 'nist-800-53',
          title: 'NIST 800-53',
          description:
            'National Institute of Standards and Technology Special Publication 800-53 sets guidelines for federal information systems.',
          icon: Building2,
        },
        {
          id: 'tsc',
          title: 'TSC',
          description:
            'Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy',
          icon: Lock,
        },
        {
          id: 'gdpr',
          title: 'GDPR',
          description:
            'General Data Protection Regulation (GDPR) sets guidelines for processing of personal data.',
          icon: FileText,
        },
        {
          id: 'hipaa',
          title: 'HIPAA',
          description:
            'Health Insurance Portability and Accountability Act of 1996 (HIPAA) provides data privacy and security provisions for safeguarding medical information.',
          icon: HeartPulse,
        },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      {/* Agent KPI Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-white border border-[#D3DAE6] rounded p-4 text-center">
        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Total agents</div>
          <div className="text-[32px] font-semibold text-[#006BB4] leading-tight mt-1">{stats.total}</div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Active agents</div>
          <div className="text-[32px] font-semibold text-[#00A389] leading-tight mt-1">{stats.active}</div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Disconnected agents</div>
          <div className="text-[32px] font-semibold text-[#BD271E] leading-tight mt-1">{stats.disconnected}</div>
        </div>

        <div
          className="cursor-pointer hover:bg-[#F8FAFC] py-2 rounded transition-colors"
          onClick={() => onNavigate('agents')}
        >
          <div className="text-[12px] text-[#5A626F] font-medium">Never connected agents</div>
          <div className="text-[32px] font-semibold text-[#64748B] leading-tight mt-1">0</div>
        </div>
      </div>

      {/* 2x2 Category Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
        {sections.map((section) => (
          <div
            key={section.title}
            className="relative border border-[#D3DAE6] rounded bg-white p-5 pt-7"
          >
            {/* Pill Header Badge */}
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white border border-[#D3DAE6] px-4 py-0.5 rounded-full text-[11px] font-bold tracking-wider text-[#1A1C21] uppercase whitespace-nowrap shadow-xs">
              {section.title}
            </div>

            {/* Modules Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              {section.modules.map((mod) => {
                const Icon = mod.icon;
                return (
                  <div
                    key={mod.id}
                    onClick={() => onNavigate(mod.id)}
                    className="border border-[#D3DAE6] hover:border-[#006BB4] rounded p-3.5 flex items-start gap-3 bg-white hover:bg-[#F8FAFC] transition-all cursor-pointer group shadow-xs"
                  >
                    <div className="mt-0.5 p-2 rounded bg-[#F5F7FA] text-[#006BB4] group-hover:bg-[#EBF5FB] group-hover:text-[#005593] transition-colors shrink-0">
                      <Icon className="w-5 h-5" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold text-[#1A1C21] group-hover:text-[#006BB4] transition-colors leading-snug">
                        {mod.title}
                      </div>
                      <div className="text-[11px] text-[#5A626F] mt-1 line-clamp-3 leading-relaxed">
                        {mod.description}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
