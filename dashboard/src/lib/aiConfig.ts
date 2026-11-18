export type AiProviderId = 'google' | 'openai' | 'anthropic' | 'pollinations' | 'experiential' | 'custom';

export interface DiscoveredAiModel {
  id: string;
  label?: string;
  free?: boolean;
  context_window?: number | null;
  chat_supported?: boolean;
}

export interface SavedAiKey {
  id: string;
  name: string;
  provider: AiProviderId | string;
  model: string;
  base_url?: string;
  api_key?: string;
  has_api_key?: boolean;
  api_key_masked?: string;
  clear_api_key?: boolean;
  models?: DiscoveredAiModel[];
  models_updated_at?: string;
}

export interface AiConfig {
  enabled: boolean;
  provider: AiProviderId | string;
  model: string;
  temperature: number;
  max_tokens: number;
  system_instruction: string;
  api_key?: string;
  has_api_key?: boolean;
  clear_api_key?: boolean;
  custom_base_url?: string;
  primary_saved_key_id?: string;
  fallback_enabled: boolean;
  fallback_provider: AiProviderId | string;
  fallback_model: string;
  fallback_api_key?: string;
  has_fallback_api_key?: boolean;
  clear_fallback_api_key?: boolean;
  fallback_base_url?: string;
  fallback_saved_key_id?: string;
  saved_api_keys?: SavedAiKey[];
}

export interface ThreatIntelSource {
  enabled: boolean;
  api_key?: string;
  has_api_key?: boolean;
  min_engines_high?: number;
  min_engines_critical?: number;
  auto_escalate?: boolean;
  min_pulses?: number;
  sync_osint?: boolean;
}

export interface ThreatIntelConfig {
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

export interface AiProviderMeta {
  id: AiProviderId;
  label: string;
  shortLabel: string;
  keyLabel: string;
  defaultModel: string;
  badgeText: string;
  supportsBaseUrl: boolean;
  baseUrlPlaceholder: string;
  presets: Array<{ id: string; label: string }>;
}

export const AI_PROVIDERS: AiProviderMeta[] = [
  {
    id: 'google',
    label: 'Google Gemini (Official REST API)',
    shortLabel: 'Google Gemini',
    keyLabel: 'GEMINI_API_KEY',
    defaultModel: 'gemini-2.5-flash',
    badgeText: 'Cloud Primary',
    supportsBaseUrl: false,
    baseUrlPlaceholder: 'https://generativelanguage.googleapis.com/v1beta',
    presets: [
      { id: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash (Cepat)' },
      { id: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro (Deep Reasoning)' },
      { id: 'gemini-1.5-flash', label: 'Gemini 1.5 Flash' },
    ],
  },
  {
    id: 'openai',
    label: 'OpenAI (GPT-4o / GPT-4.1 / o3-mini)',
    shortLabel: 'OpenAI GPT',
    keyLabel: 'OPENAI_API_KEY',
    defaultModel: 'gpt-4o-mini',
    badgeText: 'OpenAI Cloud',
    supportsBaseUrl: true,
    baseUrlPlaceholder: 'https://api.openai.com/v1 (opsional)',
    presets: [
      { id: 'gpt-4o-mini', label: 'GPT-4o Mini (Cepat & Hemat)' },
      { id: 'gpt-4o', label: 'GPT-4o (Akurasi Tinggi)' },
      { id: 'gpt-4.1-mini', label: 'GPT-4.1 Mini' },
      { id: 'o3-mini', label: 'o3-mini (Reasoning)' },
    ],
  },
  {
    id: 'anthropic',
    label: 'Anthropic (Claude Sonnet / Haiku)',
    shortLabel: 'Anthropic Claude',
    keyLabel: 'ANTHROPIC_API_KEY',
    defaultModel: 'claude-3-5-sonnet-latest',
    badgeText: 'Anthropic Cloud',
    supportsBaseUrl: true,
    baseUrlPlaceholder: 'https://api.anthropic.com/v1 (opsional)',
    presets: [
      { id: 'claude-3-5-sonnet-latest', label: 'Claude 3.5 Sonnet' },
      { id: 'claude-3-5-haiku-latest', label: 'Claude 3.5 Haiku (Cepat)' },
      { id: 'claude-3-7-sonnet-latest', label: 'Claude 3.7 Sonnet' },
    ],
  },
  {
    id: 'pollinations',
    label: 'Pollinations API (DeepSeek V4 / Open Models)',
    shortLabel: 'Pollinations',
    keyLabel: 'POLLINATIONS_API_KEY',
    defaultModel: 'deepseek/deepseek-v4-flash',
    badgeText: 'Logic Analyzer',
    supportsBaseUrl: true,
    baseUrlPlaceholder: 'https://gen.pollinations.ai/v1 (opsional)',
    presets: [
      { id: 'deepseek/deepseek-v4-flash', label: 'DeepSeek V4 Flash' },
      { id: 'deepseek-chat', label: 'DeepSeek Chat' },
      { id: 'openai', label: 'Pollinations OpenAI Router' },
    ],
  },
  {
    id: 'experiential',
    label: 'Experiential Labs (Unified AI Gateway)',
    shortLabel: 'Experiential Labs',
    keyLabel: 'EXPERIENTIAL_API_KEY',
    defaultModel: 'gpt-6-luna:free',
    badgeText: 'Gateway / Free Tier',
    supportsBaseUrl: true,
    baseUrlPlaceholder: 'https://api.experientiallabs.ai/v1 (opsional)',
    presets: [
      { id: 'gpt-6-luna:free', label: 'GPT-6 Luna (Free - Cepat & Ringkas)' },
      { id: 'gpt-6.2-astra:free', label: 'GPT-6.2 Astra (Free - Non-Reasoning)' },
      { id: 'deepseek-v4.1-flash:free', label: 'DeepSeek V4.1 Flash (Free)' },
      { id: 'qwen4-max:free', label: 'Qwen4 Max (Free - Detail)' },
    ],
  },
  {
    id: 'custom',
    label: 'Custom OpenAI-Compatible (Ollama / Groq / vLLM)',
    shortLabel: 'Custom Endpoint',
    keyLabel: 'Custom Bearer Key (opsional)',
    defaultModel: 'llama3.2:3b',
    badgeText: 'Custom / Self-Hosted',
    supportsBaseUrl: true,
    baseUrlPlaceholder: 'http://127.0.0.1:11434/v1 atau https://api.groq.com/openai/v1',
    presets: [
      { id: 'llama3.2:3b', label: 'Llama 3.2 3B (Ollama)' },
      { id: 'qwen2.5:7b', label: 'Qwen 2.5 7B (Ollama)' },
      { id: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B (Groq)' },
    ],
  },
];

export function getProviderMeta(providerId?: string): AiProviderMeta {
  const key = String(providerId || 'google').toLowerCase();
  return AI_PROVIDERS.find((p) => p.id === key) || AI_PROVIDERS[0];
}

export const DEFAULT_AI_CONFIG: AiConfig = {
  enabled: true,
  provider: 'google',
  model: 'gemini-2.5-flash',
  temperature: 0.3,
  max_tokens: 1500,
  system_instruction:
    'You are a senior SOC analyst. Respond in formal Bahasa Indonesia. Write 2-3 concise sentences. Focus on containment and severity.',
  api_key: '',
  custom_base_url: '',
  primary_saved_key_id: '',
  fallback_enabled: true,
  fallback_provider: 'pollinations',
  fallback_model: 'deepseek/deepseek-v4-flash',
  fallback_api_key: '',
  fallback_base_url: '',
  fallback_saved_key_id: '',
  saved_api_keys: [],
};

export const DEFAULT_THREAT_INTEL_CONFIG: ThreatIntelConfig = {
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
};
