'use client';

import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  Shield,
  Sliders,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Eye,
  EyeOff,
  Play,
  Save,
  Zap,
  Globe,
  Database,
  Cpu,
} from 'lucide-react';

interface AiConfig {
  enabled: boolean;
  provider: string;
  model: string;
  temperature: number;
  max_tokens: number;
  system_instruction: string;
  api_key?: string;
  has_api_key?: boolean;
  fallback_provider: string;
  fallback_model: string;
  custom_base_url?: string;
}

interface ThreatIntelSource {
  enabled: boolean;
  api_key?: string;
  has_api_key?: boolean;
  min_engines_high?: number;
  min_engines_critical?: number;
  auto_escalate?: boolean;
  min_pulses?: number;
  sync_osint?: boolean;
}

interface ThreatIntelConfig {
  consensus_mode: string;
  sources: {
    virustotal: ThreatIntelSource;
    malwarebazaar: ThreatIntelSource;
    alienvault_otx: ThreatIntelSource;
    misp: ThreatIntelSource;
  };
  cache_ttl: {
    malicious_days: number;
    clean_hours: number;
    unknown_hours: number;
  };
}

interface DynamicSettingsViewProps {
  userRole?: string;
}

export function DynamicSettingsView({ userRole = 'admin' }: DynamicSettingsViewProps) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form states
  const [aiConfig, setAiConfig] = useState<AiConfig>({
    enabled: true,
    provider: 'google',
    model: 'gemini-2.5-flash',
    temperature: 0.3,
    max_tokens: 1500,
    system_instruction: 'You are a senior SOC analyst. Respond in formal Bahasa Indonesia. Write 2-3 concise sentences. Focus on containment and severity.',
    fallback_provider: 'pollinations',
    fallback_model: 'deepseek/deepseek-v4-flash',
  });

  const [tiConfig, setTiConfig] = useState<ThreatIntelConfig>({
    consensus_mode: 'ensemble',
    sources: {
      virustotal: { enabled: true, min_engines_high: 5, min_engines_critical: 20 },
      malwarebazaar: { enabled: true, auto_escalate: true },
      alienvault_otx: { enabled: true, min_pulses: 1 },
      misp: { enabled: true, sync_osint: true },
    },
    cache_ttl: {
      malicious_days: 7,
      clean_hours: 24,
      unknown_hours: 6,
    },
  });

  // Password visibility toggles
  const [showAiKey, setShowAiKey] = useState(false);
  const [showVtKey, setShowVtKey] = useState(false);
  const [showMbKey, setShowMbKey] = useState(false);
  const [showOtxKey, setShowOtxKey] = useState(false);

  // Live AI Test State
  const [testPrompt, setTestPrompt] = useState('Analisis file mencurigakan ransom_payload.exe yang mendeteksi ekstensi terenkripsi di folder workstation.');
  const [isTestingAi, setIsTestingAi] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    model?: string;
    provider?: string;
    latency_ms?: number;
    response?: string;
    error?: string;
  } | null>(null);

  useEffect(() => {
    let ignore = false;
    async function load() {
      try {
        const res = await fetch('/api/settings/threat-intel');
        if (ignore) return;
        if (res.status === 401) {
          setError('Sesi dashboard belum aktif.');
          return;
        }
        if (res.status === 403) {
          setError('Akses ditolak: Hanya Admin dan Analyst yang dapat melihat konfigurasi sistem.');
          return;
        }
        const data = await res.json();
        if (ignore) return;
        if (!res.ok) {
          setError(data.error || 'Gagal memuat konfigurasi.');
        } else {
          if (data.ai_config) setAiConfig(data.ai_config);
          if (data.threat_intel_config) setTiConfig(data.threat_intel_config);
        }
      } catch (err) {
        if (!ignore) {
          setError(`Kesalahan jaringan: ${err instanceof Error ? err.message : String(err)}`);
        }
      } finally {
        if (!ignore) {
          setLoading(false);
        }
      }
    }
    load();
    return () => {
      ignore = true;
    };
  }, []);

  const handleSaveAll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (userRole !== 'admin') {
      setError('Hanya akun dengan peran Admin yang dapat mengubah konfigurasi sistem.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const res = await fetch('/api/settings/threat-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ai_config: aiConfig,
          threat_intel_config: tiConfig,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setError(data.error || 'Gagal menyimpan konfigurasi.');
        setSaving(false);
        return;
      }
      setSuccessMsg('Konfigurasi dinamis AI Engine & Multi-Source Threat Intel berhasil diperbarui.');
      setTimeout(() => setSuccessMsg(null), 5000);
      if (data.settings?.ai_config) setAiConfig(data.settings.ai_config);
      if (data.settings?.threat_intel_config) setTiConfig(data.settings.threat_intel_config);
    } catch (err) {
      setError(`Gagal menyimpan: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleRunAiTest = async () => {
    setIsTestingAi(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/settings/ai/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: aiConfig.provider,
          model: aiConfig.model,
          prompt: testPrompt,
          api_key: aiConfig.api_key && !aiConfig.api_key.includes('•') ? aiConfig.api_key : undefined,
        }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err) {
      setTestResult({
        success: false,
        error: `Gagal memanggil endpoint test: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setIsTestingAi(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-white border border-[#D3DAE6] rounded p-8 text-center text-[#5A626F]">
        <div className="flex items-center justify-center gap-2">
          <RefreshCw className="w-5 h-5 animate-spin text-[#006BB4]" />
          <span>Memuat konfigurasi dinamis SOAR...</span>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={handleSaveAll} className="space-y-6">
      {/* Notifications */}
      {error && (
        <div className="p-3 bg-[#FDF3F2] border border-[#F5C2C0] rounded flex items-center gap-2.5 text-[12px] text-[#BD271E]">
          <XCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-[#E6F6F4] border border-[#A3E5DD] rounded flex items-center gap-2.5 text-[12px] text-[#00A389]">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Action Header */}
      <div className="flex items-center justify-between bg-white border border-[#D3DAE6] p-4 rounded shadow-xs">
        <div>
          <h2 className="text-base font-bold text-[#1A1C21] flex items-center gap-2">
            <Sliders className="w-4 h-4 text-[#006BB4]" />
            <span>Konfigurasi Dinamis AI Engine &amp; Threat Intelligence Multi-Source</span>
          </h2>
          <p className="text-[12px] text-[#5A626F] mt-0.5">
            Ubah model kecerdasan buatan, ambang batas mitigasi, dan koroborasi intelijen tanpa perlu mengubah kode sumber atau me-restart server.
          </p>
        </div>
        {userRole === 'admin' && (
          <button
            type="submit"
            disabled={saving}
            className="h-9 px-4 bg-[#006BB4] hover:bg-[#005593] text-white rounded text-[13px] font-medium flex items-center gap-2 shadow-sm transition-colors cursor-pointer"
          >
            {saving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
            <span>Simpan Perubahan</span>
          </button>
        )}
      </div>

      {/* SECTION 1: AI Engine Configuration */}
      <div className="bg-white border border-[#D3DAE6] rounded p-5 space-y-4 shadow-xs">
        <div className="flex items-center justify-between pb-3 border-b border-[#E1E6EB]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-[#E8F3FA] rounded text-[#006BB4]">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-[14px] font-bold text-[#1A1C21]">AI Reasoning Engine (Large Language Model)</h3>
              <p className="text-[11px] text-[#5A626F]">Pengayaan narasi insiden, rekomendasi mitigasi, dan analisis triase otomatis.</p>
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={aiConfig.enabled}
              onChange={(e) => setAiConfig({ ...aiConfig, enabled: e.target.checked })}
              className="rounded text-[#006BB4] focus:ring-0"
            />
            <span className="text-[12px] font-semibold text-[#1A1C21]">Enrichment Aktif</span>
          </label>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-[13px]">
          <div>
            <label className="block text-[#1A1C21] font-medium mb-1">Provider Utama (AI Platform)</label>
            <select
              value={aiConfig.provider}
              onChange={(e) => setAiConfig({ ...aiConfig, provider: e.target.value })}
              className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] bg-white"
            >
              <option value="google">Google Gemini (Official REST API)</option>
              <option value="pollinations">Pollinations API (DeepSeek V4)</option>
              <option value="openai">OpenAI Compatible (Ollama / Local / Proxy)</option>
              <option value="custom">Custom Engine</option>
            </select>
          </div>

          <div>
            <label className="block text-[#1A1C21] font-medium mb-1">Pilihan Model AI (Model ID)</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={aiConfig.model}
                onChange={(e) => setAiConfig({ ...aiConfig, model: e.target.value })}
                placeholder="misal: gemini-2.5-flash"
                className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px]"
              />
              <select
                onChange={(e) => {
                  if (e.target.value) setAiConfig({ ...aiConfig, model: e.target.value });
                }}
                className="px-2 py-1.5 border border-[#D3DAE6] rounded text-[11px] bg-[#F8FAFC]"
                defaultValue=""
              >
                <option value="" disabled>Pilih Preset...</option>
                <option value="gemini-2.5-flash">Gemini 2.5 Flash (Rekomendasi Cepat)</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro (Deep Reasoning)</option>
                <option value="deepseek/deepseek-v4-flash">DeepSeek V4 Flash (Pollinations)</option>
                <option value="deepseek-chat">DeepSeek Chat</option>
                <option value="gpt-4o-mini">GPT-4o Mini</option>
              </select>
            </div>
            <span className="text-[11px] text-[#8A94A6]">Model dapat disetel bebas sesuai kebutuhan evaluasi penelitian.</span>
          </div>

          <div>
            <label className="block text-[#1A1C21] font-medium mb-1">
              API Key ({aiConfig.provider === 'google' ? 'GEMINI_API_KEY' : 'Provider Key'})
            </label>
            <div className="relative">
              <input
                type={showAiKey ? 'text' : 'password'}
                value={aiConfig.api_key || ''}
                onChange={(e) => setAiConfig({ ...aiConfig, api_key: e.target.value })}
                placeholder={aiConfig.has_api_key ? 'Tersimpan di server (biarkan jika tak diubah)' : 'Masukkan API Key baru'}
                className="w-full pl-3 pr-8 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px]"
              />
              <button
                type="button"
                onClick={() => setShowAiKey(!showAiKey)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#8A94A6] hover:text-[#1A1C21]"
              >
                {showAiKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[13px] pt-1">
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[#1A1C21] font-medium">Temperature: {aiConfig.temperature}</label>
              <span className="text-[11px] text-[#8A94A6]">Lebih rendah = lebih deterministik &amp; faktual</span>
            </div>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={aiConfig.temperature}
              onChange={(e) => setAiConfig({ ...aiConfig, temperature: parseFloat(e.target.value) })}
              className="w-full accent-[#006BB4]"
            />
          </div>

          <div>
            <label className="block text-[#1A1C21] font-medium mb-1">Max Output Tokens</label>
            <input
              type="number"
              min="200"
              max="4096"
              step="100"
              value={aiConfig.max_tokens}
              onChange={(e) => setAiConfig({ ...aiConfig, max_tokens: parseInt(e.target.value, 10) || 1500 })}
              className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] text-[12px]"
            />
          </div>
        </div>

        <div>
          <label className="block text-[#1A1C21] font-medium mb-1">System Instruction / Prompt Guidance</label>
          <textarea
            rows={2}
            value={aiConfig.system_instruction}
            onChange={(e) => setAiConfig({ ...aiConfig, system_instruction: e.target.value })}
            className="w-full px-3 py-2 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] text-[12px] font-sans"
            placeholder="Petunjuk gaya bahasa analisis AI untuk triage notifikasi..."
          />
        </div>

        {/* Live Test AI Inference Playground */}
        <div className="p-3.5 bg-[#F8FAFC] border border-[#E1E6EB] rounded space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-bold text-[#1A1C21] flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-[#006BB4]" />
              <span>Live AI Inference Benchmark (Uji Coba Respon Model Terpilih)</span>
            </span>
            <button
              type="button"
              onClick={handleRunAiTest}
              disabled={isTestingAi}
              className="px-3 py-1 bg-[#006BB4] hover:bg-[#005593] text-white rounded text-[11px] font-medium flex items-center gap-1.5 transition cursor-pointer"
            >
              {isTestingAi ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
              <span>{isTestingAi ? 'Menghubungi AI...' : 'Uji Inferensi Sekarang'}</span>
            </button>
          </div>
          <input
            type="text"
            value={testPrompt}
            onChange={(e) => setTestPrompt(e.target.value)}
            className="w-full px-3 py-1.5 bg-white border border-[#D3DAE6] rounded text-[12px] outline-none"
            placeholder="Masukkan prompt uji analisis..."
          />

          {testResult && (
            <div className={`p-3 rounded text-[12px] border ${testResult.success ? 'bg-[#F0FDF4] border-[#BBF7D0] text-[#166534]' : 'bg-[#FEF2F2] border-[#FECACA] text-[#991B1B]'}`}>
              <div className="flex items-center justify-between font-semibold mb-1">
                <span>{testResult.success ? `Sukses (Model: ${testResult.model || aiConfig.model})` : 'Gagal Inferensi'}</span>
                {testResult.latency_ms && <span className="font-mono text-[11px]">Latensi: {testResult.latency_ms} ms</span>}
              </div>
              <p className="leading-relaxed whitespace-pre-wrap">{testResult.response || testResult.error}</p>
            </div>
          )}
        </div>
      </div>

      {/* SECTION 2: Multi-Source Threat Intelligence Synthesis */}
      <div className="bg-white border border-[#D3DAE6] rounded p-5 space-y-4 shadow-xs">
        <div className="flex items-center justify-between pb-3 border-b border-[#E1E6EB]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-[#E8F3FA] rounded text-[#006BB4]">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-[14px] font-bold text-[#1A1C21]">Multi-Source Threat Intelligence Synthesis (Ensemble)</h3>
              <p className="text-[11px] text-[#5A626F]">
                Sintesis koroborasi multi-intelijen: VirusTotal, MalwareBazaar, AlienVault OTX, dan MISP OSINT.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-[12px]">
            <span className="text-[#5A626F] font-medium">Mode Konsensus:</span>
            <select
              value={tiConfig.consensus_mode}
              onChange={(e) => setTiConfig({ ...tiConfig, consensus_mode: e.target.value })}
              className="px-2.5 py-1 border border-[#D3DAE6] rounded text-[12px] font-semibold bg-white"
            >
              <option value="ensemble">Ensemble (Zero False-Negative)</option>
              <option value="majority">Majority Vote (Minimal 2 Sumber)</option>
              <option value="vt_first">Primary VT with Fallback</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Card VirusTotal */}
          <div className="p-4 border border-[#D3DAE6] rounded bg-[#FAFBFC] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#006BB4]" />
                <span className="font-bold text-[#1A1C21] text-[13px]">1. VirusTotal API (Reputasi Hash Global)</span>
              </div>
              <input
                type="checkbox"
                checked={tiConfig.sources.virustotal.enabled}
                onChange={(e) =>
                  setTiConfig({
                    ...tiConfig,
                    sources: {
                      ...tiConfig.sources,
                      virustotal: { ...tiConfig.sources.virustotal, enabled: e.target.checked },
                    },
                  })
                }
                className="rounded text-[#006BB4] focus:ring-0"
              />
            </div>
            <div className="grid grid-cols-2 gap-2 text-[12px]">
              <div>
                <label className="block text-[#5A626F] mb-1">Ambang Deteksi HIGH</label>
                <input
                  type="number"
                  min="1"
                  max="50"
                  value={tiConfig.sources.virustotal.min_engines_high || 5}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      sources: {
                        ...tiConfig.sources,
                        virustotal: {
                          ...tiConfig.sources.virustotal,
                          min_engines_high: parseInt(e.target.value, 10) || 5,
                        },
                      },
                    })
                  }
                  className="w-full px-2.5 py-1 border border-[#D3DAE6] rounded bg-white text-[12px]"
                />
                <span className="text-[10px] text-[#8A94A6]">Minimal engine terdeteksi</span>
              </div>
              <div>
                <label className="block text-[#5A626F] mb-1">Ambang CRITICAL</label>
                <input
                  type="number"
                  min="5"
                  max="70"
                  value={tiConfig.sources.virustotal.min_engines_critical || 20}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      sources: {
                        ...tiConfig.sources,
                        virustotal: {
                          ...tiConfig.sources.virustotal,
                          min_engines_critical: parseInt(e.target.value, 10) || 20,
                        },
                      },
                    })
                  }
                  className="w-full px-2.5 py-1 border border-[#D3DAE6] rounded bg-white text-[12px]"
                />
                <span className="text-[10px] text-[#8A94A6]">Auto-quarantine</span>
              </div>
            </div>
            <div>
              <label className="block text-[#5A626F] text-[12px] mb-1">API Key VirusTotal</label>
              <div className="relative">
                <input
                  type={showVtKey ? 'text' : 'password'}
                  value={tiConfig.sources.virustotal.api_key || ''}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      sources: {
                        ...tiConfig.sources,
                        virustotal: { ...tiConfig.sources.virustotal, api_key: e.target.value },
                      },
                    })
                  }
                  placeholder={tiConfig.sources.virustotal.has_api_key ? 'Tersimpan di server' : 'API Key VT'}
                  className="w-full pl-2.5 pr-8 py-1 border border-[#D3DAE6] rounded bg-white text-[12px] font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowVtKey(!showVtKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#8A94A6]"
                >
                  {showVtKey ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                </button>
              </div>
            </div>
          </div>

          {/* Card MalwareBazaar */}
          <div className="p-4 border border-[#D3DAE6] rounded bg-[#FAFBFC] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#006BB4]" />
                <span className="font-bold text-[#1A1C21] text-[13px]">2. MalwareBazaar (Signature Database)</span>
              </div>
              <input
                type="checkbox"
                checked={tiConfig.sources.malwarebazaar.enabled}
                onChange={(e) =>
                  setTiConfig({
                    ...tiConfig,
                    sources: {
                      ...tiConfig.sources,
                      malwarebazaar: { ...tiConfig.sources.malwarebazaar, enabled: e.target.checked },
                    },
                  })
                }
                className="rounded text-[#006BB4] focus:ring-0"
              />
            </div>
            <div className="text-[12px] space-y-1.5 pt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={tiConfig.sources.malwarebazaar.auto_escalate ?? true}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      sources: {
                        ...tiConfig.sources,
                        malwarebazaar: { ...tiConfig.sources.malwarebazaar, auto_escalate: e.target.checked },
                      },
                    })
                  }
                  className="rounded text-[#006BB4] focus:ring-0"
                />
                <span className="text-[#1A1C21]">Eskalasi Otomatis ke HIGH jika signature terdaftar</span>
              </label>
              <p className="text-[11px] text-[#8A94A6]">
                Mencegah celah false-negative ketika hash sampel baru belum terindeks penuh di engine antivirus VT.
              </p>
            </div>
            <div>
              <label className="block text-[#5A626F] text-[12px] mb-1">API Key MalwareBazaar (Auth-Key)</label>
              <div className="relative">
                <input
                  type={showMbKey ? 'text' : 'password'}
                  value={tiConfig.sources.malwarebazaar.api_key || ''}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      sources: {
                        ...tiConfig.sources,
                        malwarebazaar: { ...tiConfig.sources.malwarebazaar, api_key: e.target.value },
                      },
                    })
                  }
                  placeholder={tiConfig.sources.malwarebazaar.has_api_key ? 'Tersimpan di server' : 'API Key MB'}
                  className="w-full pl-2.5 pr-8 py-1 border border-[#D3DAE6] rounded bg-white text-[12px] font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowMbKey(!showMbKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#8A94A6]"
                >
                  {showMbKey ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                </button>
              </div>
            </div>
          </div>

          {/* Card AlienVault OTX */}
          <div className="p-4 border border-[#D3DAE6] rounded bg-[#FAFBFC] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#006BB4]" />
                <span className="font-bold text-[#1A1C21] text-[13px]">3. AlienVault OTX (Open Threat Exchange)</span>
              </div>
              <input
                type="checkbox"
                checked={tiConfig.sources.alienvault_otx.enabled}
                onChange={(e) =>
                  setTiConfig({
                    ...tiConfig,
                    sources: {
                      ...tiConfig.sources,
                      alienvault_otx: { ...tiConfig.sources.alienvault_otx, enabled: e.target.checked },
                    },
                  })
                }
                className="rounded text-[#006BB4] focus:ring-0"
              />
            </div>
            <div className="text-[12px]">
              <label className="block text-[#5A626F] mb-1">Ambang Batas Pulses (Threat Pulses)</label>
              <input
                type="number"
                min="1"
                max="10"
                value={tiConfig.sources.alienvault_otx.min_pulses || 1}
                onChange={(e) =>
                  setTiConfig({
                    ...tiConfig,
                    sources: {
                      ...tiConfig.sources,
                      alienvault_otx: {
                        ...tiConfig.sources.alienvault_otx,
                        min_pulses: parseInt(e.target.value, 10) || 1,
                      },
                    },
                  })
                }
                className="w-full px-2.5 py-1 border border-[#D3DAE6] rounded bg-white text-[12px]"
              />
              <span className="text-[10px] text-[#8A94A6]">Minimal pulse untuk mengindikasikan file berbahaya</span>
            </div>
            <div>
              <label className="block text-[#5A626F] text-[12px] mb-1">API Key OTX</label>
              <div className="relative">
                <input
                  type={showOtxKey ? 'text' : 'password'}
                  value={tiConfig.sources.alienvault_otx.api_key || ''}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      sources: {
                        ...tiConfig.sources,
                        alienvault_otx: { ...tiConfig.sources.alienvault_otx, api_key: e.target.value },
                      },
                    })
                  }
                  placeholder={tiConfig.sources.alienvault_otx.has_api_key ? 'Tersimpan di server' : 'API Key OTX'}
                  className="w-full pl-2.5 pr-8 py-1 border border-[#D3DAE6] rounded bg-white text-[12px] font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowOtxKey(!showOtxKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#8A94A6]"
                >
                  {showOtxKey ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                </button>
              </div>
            </div>
          </div>

          {/* Card MISP OSINT & Cache TTL */}
          <div className="p-4 border border-[#D3DAE6] rounded bg-[#FAFBFC] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#006BB4]" />
                <span className="font-bold text-[#1A1C21] text-[13px]">4. Cache &amp; Quota Optimization</span>
              </div>
              <input
                type="checkbox"
                checked={tiConfig.sources.misp.enabled}
                onChange={(e) =>
                  setTiConfig({
                    ...tiConfig,
                    sources: {
                      ...tiConfig.sources,
                      misp: { ...tiConfig.sources.misp, enabled: e.target.checked },
                    },
                  })
                }
                className="rounded text-[#006BB4] focus:ring-0"
              />
            </div>
            <div className="grid grid-cols-3 gap-2 text-[12px]">
              <div>
                <label className="block text-[#5A626F] mb-1">TTL Malicious</label>
                <input
                  type="number"
                  min="1"
                  max="30"
                  value={tiConfig.cache_ttl.malicious_days}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      cache_ttl: { ...tiConfig.cache_ttl, malicious_days: parseInt(e.target.value, 10) || 7 },
                    })
                  }
                  className="w-full px-2 py-1 border border-[#D3DAE6] rounded bg-white text-[11px]"
                />
                <span className="text-[10px] text-[#8A94A6]">Hari</span>
              </div>
              <div>
                <label className="block text-[#5A626F] mb-1">TTL Clean</label>
                <input
                  type="number"
                  min="1"
                  max="168"
                  value={tiConfig.cache_ttl.clean_hours}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      cache_ttl: { ...tiConfig.cache_ttl, clean_hours: parseInt(e.target.value, 10) || 24 },
                    })
                  }
                  className="w-full px-2 py-1 border border-[#D3DAE6] rounded bg-white text-[11px]"
                />
                <span className="text-[10px] text-[#8A94A6]">Jam</span>
              </div>
              <div>
                <label className="block text-[#5A626F] mb-1">TTL Unknown</label>
                <input
                  type="number"
                  min="1"
                  max="24"
                  value={tiConfig.cache_ttl.unknown_hours}
                  onChange={(e) =>
                    setTiConfig({
                      ...tiConfig,
                      cache_ttl: { ...tiConfig.cache_ttl, unknown_hours: parseInt(e.target.value, 10) || 6 },
                    })
                  }
                  className="w-full px-2 py-1 border border-[#D3DAE6] rounded bg-white text-[11px]"
                />
                <span className="text-[10px] text-[#8A94A6]">Jam</span>
              </div>
            </div>
            <p className="text-[11px] text-[#8A94A6] pt-1 leading-relaxed">
              Diferensial TTL melindungi kuota gratis API eksternal (maksimal 4 request/menit pada VT) saat armada 100 endpoint mengalami lonjakan insiden serentak.
            </p>
          </div>
        </div>
      </div>
    </form>
  );
}
