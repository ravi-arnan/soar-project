'use client';

import React, { useState, useEffect } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import {
  AI_PROVIDERS,
  DEFAULT_AI_CONFIG,
  DEFAULT_THREAT_INTEL_CONFIG,
  getProviderMeta,
  type AiConfig,
  type DiscoveredAiModel,
  type SavedAiKey,
  type ThreatIntelConfig,
} from '@/lib/aiConfig';
import { WuiCallOut, WuiPageHeader, WuiPanel } from '../wui/WuiPrimitives';

interface DynamicSettingsViewProps {
  userRole?: string;
}

function cleanSecretInput(val?: string): string | undefined {
  return val && !val.includes('•') ? val : undefined;
}

function applySavedKeyToSlot(
  prev: AiConfig,
  slot: 'primary' | 'fallback',
  saved: SavedAiKey
): AiConfig {
  const meta = getProviderMeta(saved.provider);
  const nextModel = saved.model || meta.defaultModel;
  if (slot === 'primary') {
    return {
      ...prev,
      provider: saved.provider,
      model: nextModel,
      custom_base_url: saved.base_url || '',
      api_key: saved.api_key || '',
      has_api_key: Boolean(saved.has_api_key || (saved.api_key && saved.api_key.trim())),
      clear_api_key: false,
      primary_saved_key_id: saved.id,
    };
  }
  return {
    ...prev,
    fallback_enabled: true,
    fallback_provider: saved.provider,
    fallback_model: nextModel,
    fallback_base_url: saved.base_url || '',
    fallback_api_key: saved.api_key || '',
    has_fallback_api_key: Boolean(saved.has_api_key || (saved.api_key && saved.api_key.trim())),
    clear_fallback_api_key: false,
    fallback_saved_key_id: saved.id,
  };
}

interface ProviderFieldsProps {
  title: string;
  subtitle: string;
  provider: string;
  model: string;
  apiKey?: string;
  hasApiKey?: boolean;
  baseUrl?: string;
  showKey: boolean;
  savedKeys: SavedAiKey[];
  selectedSavedKeyId?: string;
  availableModels: DiscoveredAiModel[];
  loadingModels?: boolean;
  modelsStatus?: string | null;
  onToggleShowKey: () => void;
  onProviderChange: (nextProvider: string, defaultModel: string) => void;
  onModelChange: (nextModel: string) => void;
  onApiKeyChange: (nextKey: string) => void;
  onClearApiKey: () => void;
  onBaseUrlChange: (nextUrl: string) => void;
  onSelectSavedKey: (savedKeyId: string) => void;
  onFetchModels: () => void;
  onSaveCurrentToSavedKeys: () => void;
}

function ProviderConfigFields({
  title,
  subtitle,
  provider,
  model,
  apiKey,
  hasApiKey,
  baseUrl,
  showKey,
  savedKeys,
  selectedSavedKeyId,
  availableModels,
  loadingModels,
  modelsStatus,
  onToggleShowKey,
  onProviderChange,
  onModelChange,
  onApiKeyChange,
  onClearApiKey,
  onBaseUrlChange,
  onSelectSavedKey,
  onFetchModels,
  onSaveCurrentToSavedKeys,
}: ProviderFieldsProps) {
  const meta = getProviderMeta(provider);
  const canSaveProfile = Boolean((apiKey && apiKey.trim()) || hasApiKey);

  return (
    <div className="p-4 bg-[#FAFBFD] border border-[#E1E6EB] rounded space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="text-[13px] font-semibold text-[#1A1C21]">{title}</div>
          <div className="text-[11px] text-[#5A626F]">{subtitle}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {savedKeys.length > 0 && (
            <select
              value={selectedSavedKeyId || ''}
              onChange={(e) => {
                if (e.target.value) onSelectSavedKey(e.target.value);
              }}
              aria-label={`Switch Saved API Key untuk ${title}`}
              className="h-7 px-2 border border-[#D3DAE6] rounded-[4px] text-[11px] bg-white text-[#1A1C21] max-w-[240px]"
            >
              <option value="">Switch Saved Key...</option>
              {savedKeys.map((sk) => (
                <option key={sk.id} value={sk.id}>
                  {sk.name} ({getProviderMeta(sk.provider).shortLabel})
                </option>
              ))}
            </select>
          )}
          {canSaveProfile && (
            <button
              type="button"
              onClick={onSaveCurrentToSavedKeys}
              className="h-7 px-2.5 bg-white hover:bg-[#F5F7FA] text-[#006BB4] border border-[#D3DAE6] rounded-[4px] text-[11px] font-medium flex items-center gap-1 cursor-pointer"
            >
              <WuiIcon type="listAdd" size="xs" />
              <span>Simpan ke Saved Keys</span>
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-[13px]">
        <div>
          <label className="block text-[#1A1C21] font-medium mb-1">Provider Platform</label>
          <select
            value={provider}
            onChange={(e) => {
              const nextMeta = getProviderMeta(e.target.value);
              onProviderChange(e.target.value, nextMeta.defaultModel);
            }}
            className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] bg-white"
          >
            {AI_PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="block text-[#1A1C21] font-medium">Model ID</label>
            <button
              type="button"
              onClick={onFetchModels}
              disabled={loadingModels}
              className="text-[11px] text-[#006BB4] hover:underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
            >
              <WuiIcon type="refresh" size="xs" className={loadingModels ? 'animate-spin' : ''} />
              <span>{loadingModels ? 'Memuat...' : 'Cek Model'}</span>
            </button>
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={model}
              onChange={(e) => onModelChange(e.target.value)}
              placeholder={meta.defaultModel}
              className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px] bg-white"
            />
            <select
              onChange={(e) => {
                if (e.target.value) onModelChange(e.target.value);
              }}
              className="px-2 py-1.5 border border-[#D3DAE6] rounded text-[11px] bg-white max-w-[165px]"
              value=""
            >
              <option value="" disabled>
                {availableModels.length > 0 ? `Model (${availableModels.length})...` : 'Preset...'}
              </option>
              {availableModels.length > 0 && (
                <optgroup label={`Tersedia di Key (${availableModels.length})`}>
                  {availableModels.map((m) => (
                    <option key={`live-${m.id}`} value={m.id} disabled={m.chat_supported === false}>
                      {m.label || m.id}
                    </option>
                  ))}
                </optgroup>
              )}
              <optgroup label="Preset Bawaan">
                {meta.presets.map((preset) => (
                  <option key={preset.id} value={preset.id}>
                    {preset.label}
                  </option>
                ))}
              </optgroup>
            </select>
          </div>
          {modelsStatus && (
            <div className="text-[11px] text-[#535966] mt-1 font-mono">{modelsStatus}</div>
          )}
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="block text-[#1A1C21] font-medium">
              API Key ({meta.keyLabel})
            </label>
            {hasApiKey && (
              <button
                type="button"
                onClick={onClearApiKey}
                className="text-[11px] text-[#BD271E] hover:underline cursor-pointer"
              >
                Hapus Key
              </button>
            )}
          </div>
          <div className="relative">
            <input
              type={showKey ? 'text' : 'password'}
              value={apiKey || ''}
              onChange={(e) => onApiKeyChange(e.target.value)}
              placeholder={
                hasApiKey ? 'Tersimpan di server (biarkan jika tak diubah)' : `Masukkan ${meta.keyLabel}`
              }
              className="w-full pl-3 pr-8 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px] bg-white"
            />
            <button
              type="button"
              onClick={onToggleShowKey}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#8A94A6] hover:text-[#1A1C21]"
            >
              {showKey ? <WuiIcon type="eyeClosed" size="s" /> : <WuiIcon type="eye" size="s" />}
            </button>
          </div>
        </div>
      </div>

      {meta.supportsBaseUrl && (
        <div className="text-[12px]">
          <label className="block text-[#1A1C21] font-medium mb-1">
            Base URL Endpoint ({provider === 'custom' ? 'Wajib untuk Custom HTTP' : 'Opsional / Proxy'})
          </label>
          <input
            type="text"
            value={baseUrl || ''}
            onChange={(e) => onBaseUrlChange(e.target.value)}
            placeholder={meta.baseUrlPlaceholder}
            className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px] bg-white"
          />
        </div>
      )}
    </div>
  );
}

export function DynamicSettingsView({ userRole = 'viewer' }: DynamicSettingsViewProps) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingSavedKeys, setSavingSavedKeys] = useState(false);
  const [savedKeysFeedback, setSavedKeysFeedback] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form states
  const [aiConfig, setAiConfig] = useState<AiConfig>(DEFAULT_AI_CONFIG);
  const [tiConfig, setTiConfig] = useState<ThreatIntelConfig>(DEFAULT_THREAT_INTEL_CONFIG);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);

  // Password visibility toggles
  const [showAiKey, setShowAiKey] = useState(false);
  const [showFallbackKey, setShowFallbackKey] = useState(false);
  const [showNewSavedKey, setShowNewSavedKey] = useState(false);
  const [showVtKey, setShowVtKey] = useState(false);
  const [showMbKey, setShowMbKey] = useState(false);
  const [showOtxKey, setShowOtxKey] = useState(false);

  // Dynamic model discovery state per slot & saved profile
  const [slotModels, setSlotModels] = useState<{ primary: DiscoveredAiModel[]; fallback: DiscoveredAiModel[] }>({
    primary: [],
    fallback: [],
  });
  const [loadingModelsKey, setLoadingModelsKey] = useState<string | null>(null);
  const [slotModelsStatus, setSlotModelsStatus] = useState<{ primary: string | null; fallback: string | null }>({
    primary: null,
    fallback: null,
  });

  // Saved API Keys inline add form
  const [showAddSavedKey, setShowAddSavedKey] = useState(false);
  const [newSavedKey, setNewSavedKey] = useState<{
    name: string;
    provider: string;
    model: string;
    api_key: string;
    base_url: string;
    models: DiscoveredAiModel[];
  }>({
    name: '',
    provider: 'experiential',
    model: 'gpt-6-luna:free',
    api_key: '',
    base_url: '',
    models: [],
  });
  const [newSavedModelsStatus, setNewSavedModelsStatus] = useState<string | null>(null);

  // Live AI Test State
  const [testPrompt, setTestPrompt] = useState(
    'Analisis file mencurigakan ransom_payload.exe yang mendeteksi ekstensi terenkripsi di folder workstation.'
  );
  const [isTestingAi, setIsTestingAi] = useState(false);
  const [savedKeyTests, setSavedKeyTests] = useState<
    Record<
      string,
      {
        loading: boolean;
        success?: boolean;
        response?: string;
        latency_ms?: number;
        error?: string;
      }
    >
  >({});
  const [testResult, setTestResult] = useState<{
    success: boolean;
    model?: string;
    provider?: string;
    latency_ms?: number;
    response?: string;
    error?: string;
    used_fallback?: boolean;
    primary_error?: string;
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
          if (data.ai_config) setAiConfig({ ...DEFAULT_AI_CONFIG, ...data.ai_config });
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

  const updateAi = (updater: (prev: AiConfig) => AiConfig) => {
    setAiConfig((prev) => updater(prev));
    setHasUnsavedChanges(true);
  };

  const savedKeys = aiConfig.saved_api_keys || [];

  const resolveAvailableModels = (slot: 'primary' | 'fallback'): DiscoveredAiModel[] => {
    const live = slotModels[slot];
    if (live.length > 0) return live;
    const savedId = slot === 'primary' ? aiConfig.primary_saved_key_id : aiConfig.fallback_saved_key_id;
    const matched = savedKeys.find((k) => k.id === savedId);
    if (matched?.models && matched.models.length > 0) return matched.models;
    const prov = slot === 'primary' ? aiConfig.provider : aiConfig.fallback_provider;
    const sameProv = savedKeys.find((k) => k.provider === prov && k.models && k.models.length > 0);
    return sameProv?.models || [];
  };

  const fetchModelsFromServer = async (params: {
    keyTag: string;
    provider: string;
    api_key?: string;
    base_url?: string;
    saved_key_id?: string;
    slot?: 'primary' | 'fallback';
  }): Promise<{ ok: boolean; models: DiscoveredAiModel[]; statusText: string }> => {
    setLoadingModelsKey(params.keyTag);
    try {
      const res = await fetch('/api/settings/ai/models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: params.provider,
          api_key: cleanSecretInput(params.api_key),
          base_url: params.base_url,
          saved_key_id: params.saved_key_id,
          slot: params.slot,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        return { ok: false, models: [], statusText: data.error || 'Gagal memuat daftar model' };
      }
      const list: DiscoveredAiModel[] = Array.isArray(data.models) ? data.models : [];
      const freeCount = typeof data.free_count === 'number' ? data.free_count : list.filter((m) => m.free).length;
      const summary =
        freeCount > 0
          ? `${list.length} model tersedia (${freeCount} free)`
          : `${list.length} model tersedia`;
      return { ok: true, models: list, statusText: summary };
    } catch (err) {
      return {
        ok: false,
        models: [],
        statusText: `Error: ${err instanceof Error ? err.message : String(err)}`,
      };
    } finally {
      setLoadingModelsKey(null);
    }
  };

  const handleFetchSlotModels = async (slot: 'primary' | 'fallback') => {
    const isPrimary = slot === 'primary';
    const provider = isPrimary ? aiConfig.provider : aiConfig.fallback_provider;
    const apiKey = isPrimary ? aiConfig.api_key : aiConfig.fallback_api_key;
    const baseUrl = isPrimary ? aiConfig.custom_base_url : aiConfig.fallback_base_url;
    const savedId = isPrimary ? aiConfig.primary_saved_key_id : aiConfig.fallback_saved_key_id;

    const result = await fetchModelsFromServer({
      keyTag: slot,
      provider,
      api_key: apiKey,
      base_url: baseUrl,
      saved_key_id: savedId,
      slot,
    });
    setSlotModelsStatus((prev) => ({ ...prev, [slot]: result.statusText }));
    if (result.ok) {
      setSlotModels((prev) => ({ ...prev, [slot]: result.models }));
      if (savedId) {
        const nowIso = new Date().toISOString();
        updateAi((prev) => ({
          ...prev,
          saved_api_keys: (prev.saved_api_keys || []).map((sk) =>
            sk.id === savedId ? { ...sk, models: result.models, models_updated_at: nowIso } : sk
          ),
        }));
      }
    }
  };

  const persistSavedKeys = async (
    nextSavedKeys: SavedAiKey[],
    options?: {
      extraAiFields?: Partial<AiConfig>;
      successText?: string;
    }
  ): Promise<boolean> => {
    if (userRole !== 'admin') {
      const msg = 'Hanya akun dengan peran Admin yang dapat mengubah Saved API Keys.';
      setSavedKeysFeedback({ tone: 'danger', text: msg });
      setError(msg);
      return false;
    }
    setSavingSavedKeys(true);
    setSavedKeysFeedback(null);
    setError(null);
    try {
      const res = await fetch('/api/settings/threat-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ai_config: {
            saved_api_keys: nextSavedKeys,
            ...(options?.extraAiFields || {}),
          },
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.success) {
        const errText = data.error || `Gagal menyimpan Saved API Keys (HTTP ${res.status}).`;
        setSavedKeysFeedback({ tone: 'danger', text: errText });
        setError(errText);
        return false;
      }
      const serverAi = data.settings?.ai_config as AiConfig | undefined;
      setAiConfig((prev) => ({
        ...prev,
        ...(options?.extraAiFields || {}),
        ...(options?.extraAiFields?.primary_saved_key_id && serverAi
          ? { api_key: serverAi.api_key || prev.api_key, has_api_key: serverAi.has_api_key ?? prev.has_api_key }
          : {}),
        ...(options?.extraAiFields?.fallback_saved_key_id && serverAi
          ? {
              fallback_api_key: serverAi.fallback_api_key || prev.fallback_api_key,
              has_fallback_api_key: serverAi.has_fallback_api_key ?? prev.has_fallback_api_key,
            }
          : {}),
        saved_api_keys: Array.isArray(serverAi?.saved_api_keys) ? serverAi.saved_api_keys : nextSavedKeys,
      }));
      if (options?.successText) {
        setSavedKeysFeedback({ tone: 'success', text: options.successText });
      }
      return true;
    } catch (err) {
      const errText = `Gagal menyimpan Saved API Keys: ${err instanceof Error ? err.message : String(err)}`;
      setSavedKeysFeedback({ tone: 'danger', text: errText });
      setError(errText);
      return false;
    } finally {
      setSavingSavedKeys(false);
    }
  };

  const handleFetchSavedKeyModels = async (saved: SavedAiKey) => {
    const result = await fetchModelsFromServer({
      keyTag: `saved:${saved.id}`,
      provider: saved.provider,
      api_key: saved.api_key,
      base_url: saved.base_url,
      saved_key_id: saved.id,
    });
    if (!result.ok) {
      setSavedKeysFeedback({ tone: 'danger', text: result.statusText });
      setError(result.statusText);
      return;
    }
    const nowIso = new Date().toISOString();
    const nextSavedKeys = savedKeys.map((sk) =>
      sk.id === saved.id ? { ...sk, models: result.models, models_updated_at: nowIso } : sk
    );
    await persistSavedKeys(nextSavedKeys, {
      successText: `Berhasil memuat dan menyimpan ${result.statusText} untuk '${saved.name}'.`,
    });
  };

  const handleTestSavedKey = async (saved: SavedAiKey) => {
    setSavedKeyTests((prev) => ({ ...prev, [saved.id]: { loading: true } }));
    try {
      const res = await fetch('/api/settings/ai/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: 'primary',
          provider: saved.provider,
          model: saved.model,
          prompt: 'Balas hanya dengan satu kata: OK',
          api_key: cleanSecretInput(saved.api_key),
          base_url: saved.base_url || '',
          saved_key_id: saved.id,
          temperature: 0,
          max_tokens: 128,
          system_instruction: 'Kamu adalah endpoint diagnostik. Balas hanya dengan satu kata: OK',
        }),
      });
      const data = (await res.json()) as {
        success?: boolean;
        response?: string;
        latency_ms?: number;
        error?: string;
      };
      setSavedKeyTests((prev) => ({
        ...prev,
        [saved.id]: {
          loading: false,
          success: Boolean(res.ok && data.success),
          response: data.response,
          latency_ms: data.latency_ms,
          error: data.error || (!res.ok ? `HTTP ${res.status}` : undefined),
        },
      }));
    } catch (err) {
      setSavedKeyTests((prev) => ({
        ...prev,
        [saved.id]: {
          loading: false,
          success: false,
          error: err instanceof Error ? err.message : 'Gagal menghubungi server',
        },
      }));
    }
  };

  const handleSaveSlotToSavedKeys = async (slot: 'primary' | 'fallback') => {
    const isPrimary = slot === 'primary';
    const provider = isPrimary ? aiConfig.provider : aiConfig.fallback_provider;
    const model = isPrimary ? aiConfig.model : aiConfig.fallback_model;
    const apiKey = isPrimary ? aiConfig.api_key : aiConfig.fallback_api_key;
    const hasKey = isPrimary ? aiConfig.has_api_key : aiConfig.has_fallback_api_key;
    const baseUrl = isPrimary ? aiConfig.custom_base_url : aiConfig.fallback_base_url;
    const meta = getProviderMeta(provider);
    const id = `key_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const models = resolveAvailableModels(slot);
    const entry: SavedAiKey = {
      id,
      name: `${meta.shortLabel} (${model || meta.defaultModel})`,
      provider,
      model: model || meta.defaultModel,
      base_url: baseUrl || '',
      api_key: apiKey || '',
      has_api_key: Boolean(hasKey || (apiKey && apiKey.trim())),
      models,
      models_updated_at: models.length > 0 ? new Date().toISOString() : '',
    };
    const nextSavedKeys = [...savedKeys, entry];
    const extraAiFields: Partial<AiConfig> = isPrimary
      ? { primary_saved_key_id: id }
      : { fallback_saved_key_id: id };
    await persistSavedKeys(nextSavedKeys, {
      extraAiFields,
      successText: `Profil '${entry.name}' berhasil disimpan ke Saved API Keys.`,
    });
  };

  const handleAddNewSavedKey = async () => {
    const meta = getProviderMeta(newSavedKey.provider);
    if (!newSavedKey.api_key.trim() && newSavedKey.provider !== 'custom') {
      const msg = 'Masukkan API Key sebelum menyimpan profil baru.';
      setSavedKeysFeedback({ tone: 'danger', text: msg });
      setError(msg);
      return;
    }
    const id = `key_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const entry: SavedAiKey = {
      id,
      name: newSavedKey.name.trim() || `${meta.shortLabel} (${newSavedKey.model || meta.defaultModel})`,
      provider: newSavedKey.provider,
      model: newSavedKey.model.trim() || meta.defaultModel,
      base_url: newSavedKey.base_url.trim(),
      api_key: newSavedKey.api_key.trim(),
      has_api_key: Boolean(newSavedKey.api_key.trim()),
      models: newSavedKey.models,
      models_updated_at: newSavedKey.models.length > 0 ? new Date().toISOString() : '',
    };
    const ok = await persistSavedKeys([...savedKeys, entry], {
      successText: `API key '${entry.name}' berhasil disimpan ke server.`,
    });
    if (!ok) return;
    setNewSavedKey({
      name: '',
      provider: 'experiential',
      model: 'gpt-6-luna:free',
      api_key: '',
      base_url: '',
      models: [],
    });
    setNewSavedModelsStatus(null);
    setShowAddSavedKey(false);
  };

  const handleUpdateSavedKeyModel = async (sk: SavedAiKey, nextModel: string) => {
    const nextSavedKeys = savedKeys.map((item) => (item.id === sk.id ? { ...item, model: nextModel } : item));
    const extraAiFields: Partial<AiConfig> = {
      ...(aiConfig.primary_saved_key_id === sk.id ? { model: nextModel } : {}),
      ...(aiConfig.fallback_saved_key_id === sk.id ? { fallback_model: nextModel } : {}),
    };
    await persistSavedKeys(nextSavedKeys, {
      extraAiFields,
      successText: `Model '${sk.name}' diperbarui ke '${nextModel}'.`,
    });
  };

  const handleDeleteSavedKey = async (sk: SavedAiKey) => {
    const nextSavedKeys = savedKeys.filter((item) => item.id !== sk.id);
    const extraAiFields: Partial<AiConfig> = {
      ...(aiConfig.primary_saved_key_id === sk.id ? { primary_saved_key_id: '' } : {}),
      ...(aiConfig.fallback_saved_key_id === sk.id ? { fallback_saved_key_id: '' } : {}),
    };
    await persistSavedKeys(nextSavedKeys, {
      extraAiFields,
      successText: `API key '${sk.name}' telah dihapus.`,
    });
  };

  const handleSwitchToSavedKey = async (slot: 'primary' | 'fallback', savedId: string) => {
    const found = savedKeys.find((k) => k.id === savedId);
    if (!found) return;
    const nextAi = applySavedKeyToSlot(aiConfig, slot, found);
    setAiConfig(nextAi);
    if (found.models && found.models.length > 0) {
      setSlotModels((prev) => ({ ...prev, [slot]: found.models || [] }));
      const freeCount = found.models.filter((m) => m.free).length;
      setSlotModelsStatus((prev) => ({
        ...prev,
        [slot]:
          freeCount > 0
            ? `${found.models?.length} model tersedia (${freeCount} free)`
            : `${found.models?.length} model tersedia`,
      }));
    } else {
      setSlotModels((prev) => ({ ...prev, [slot]: [] }));
      setSlotModelsStatus((prev) => ({ ...prev, [slot]: null }));
    }
    const extraAiFields: Partial<AiConfig> =
      slot === 'primary'
        ? {
            provider: nextAi.provider,
            model: nextAi.model,
            custom_base_url: nextAi.custom_base_url,
            primary_saved_key_id: nextAi.primary_saved_key_id,
          }
        : {
            fallback_enabled: nextAi.fallback_enabled,
            fallback_provider: nextAi.fallback_provider,
            fallback_model: nextAi.fallback_model,
            fallback_base_url: nextAi.fallback_base_url,
            fallback_saved_key_id: nextAi.fallback_saved_key_id,
          };
    await persistSavedKeys(savedKeys, {
      extraAiFields,
      successText: `Profil '${found.name}' aktif sebagai ${slot === 'primary' ? 'Primary' : 'Fallback'}.`,
    });
  };

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
      setHasUnsavedChanges(false);
      setTimeout(() => setSuccessMsg(null), 5000);
      if (data.settings?.ai_config) setAiConfig({ ...DEFAULT_AI_CONFIG, ...data.settings.ai_config });
      if (data.settings?.threat_intel_config) setTiConfig(data.settings.threat_intel_config);
    } catch (err) {
      setError(`Gagal menyimpan: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleRunAiTest = async (target: 'primary' | 'fallback' | 'auto' = 'primary') => {
    setIsTestingAi(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/settings/ai/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          provider: aiConfig.provider,
          model: aiConfig.model,
          prompt: testPrompt,
          api_key: cleanSecretInput(aiConfig.api_key),
          base_url: aiConfig.custom_base_url,
          saved_key_id: aiConfig.primary_saved_key_id,
          temperature: aiConfig.temperature,
          max_tokens: aiConfig.max_tokens,
          system_instruction: aiConfig.system_instruction,
          fallback: {
            enabled: aiConfig.fallback_enabled,
            provider: aiConfig.fallback_provider,
            model: aiConfig.fallback_model,
            api_key: cleanSecretInput(aiConfig.fallback_api_key),
            base_url: aiConfig.fallback_base_url,
            saved_key_id: aiConfig.fallback_saved_key_id,
          },
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
      <WuiPanel>
        <div className="py-6 flex items-center justify-center gap-2 text-[#535966]">
          <WuiIcon type="refresh" size="m" className="animate-spin text-[#006BB4]" />
          <span>Memuat konfigurasi dinamis SOAR...</span>
        </div>
      </WuiPanel>
    );
  }

  return (
    <form onSubmit={handleSaveAll} className="space-y-4">
      {error && <WuiCallOut tone="danger">{error}</WuiCallOut>}
      {successMsg && <WuiCallOut tone="success">{successMsg}</WuiCallOut>}
      {hasUnsavedChanges && (
        <WuiCallOut tone="warning">
          Ada perubahan konfigurasi atau Saved API Keys yang belum disimpan. Klik tombol Simpan Perubahan di kanan atas untuk menerapkan ke server dan pipeline n8n.
        </WuiCallOut>
      )}

      <WuiPageHeader
        title="Konfigurasi Dinamis AI Engine &amp; Threat Intelligence"
        description="Atur provider LLM utama dan fallback, API key, serta bobot koroborasi multi-intelijen secara runtime tanpa restart server."
        actions={
          userRole === 'admin' && (
            <button
              type="submit"
              disabled={saving}
              className="h-8 px-3.5 bg-[#006BB4] hover:bg-[#00538C] text-white rounded-[4px] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
            >
              {saving ? <WuiIcon type="refresh" size="s" className="animate-spin" /> : <WuiIcon type="save" size="s" />}
              <span>Simpan Perubahan</span>
            </button>
          )
        }
      />

      {/* SECTION 1: AI Engine Configuration */}
      <WuiPanel
        title="AI Reasoning Engine (Large Language Model)"
        subtitle="Pengayaan narasi insiden, rekomendasi mitigasi, dan analisis triase otomatis."
        accentColor="#006BB4"
        right={
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={aiConfig.enabled}
              onChange={(e) => updateAi((prev) => ({ ...prev, enabled: e.target.checked }))}
              className="rounded-[2px] text-[#006BB4] focus:ring-0"
            />
            <span className="text-[12px] font-semibold text-[#1A1C21]">Enrichment Aktif</span>
          </label>
        }
        bodyClassName="p-4 space-y-4"
      >

        <ProviderConfigFields
          title="Engine Penalaran Utama (Primary LLM)"
          subtitle="Dipanggil pertama kali saat insiden membutuhkan analisis naratif dan rekomendasi mitigasi."
          provider={aiConfig.provider}
          model={aiConfig.model}
          apiKey={aiConfig.api_key}
          hasApiKey={aiConfig.has_api_key}
          baseUrl={aiConfig.custom_base_url}
          showKey={showAiKey}
          savedKeys={savedKeys}
          selectedSavedKeyId={aiConfig.primary_saved_key_id}
          availableModels={resolveAvailableModels('primary')}
          loadingModels={loadingModelsKey === 'primary'}
          modelsStatus={slotModelsStatus.primary}
          onToggleShowKey={() => setShowAiKey(!showAiKey)}
          onProviderChange={(nextProvider, defaultModel) => {
            setSlotModels((prev) => ({ ...prev, primary: [] }));
            setSlotModelsStatus((prev) => ({ ...prev, primary: null }));
            updateAi((prev) => ({
              ...prev,
              provider: nextProvider,
              model: defaultModel,
              primary_saved_key_id: '',
              clear_api_key: false,
            }));
          }}
          onModelChange={(nextModel) => updateAi((prev) => ({ ...prev, model: nextModel }))}
          onApiKeyChange={(nextKey) =>
            updateAi((prev) => ({ ...prev, api_key: nextKey, primary_saved_key_id: '', clear_api_key: false }))
          }
          onClearApiKey={() =>
            updateAi((prev) => ({
              ...prev,
              api_key: '',
              has_api_key: false,
              primary_saved_key_id: '',
              clear_api_key: true,
            }))
          }
          onBaseUrlChange={(nextUrl) => updateAi((prev) => ({ ...prev, custom_base_url: nextUrl }))}
          onSelectSavedKey={(savedId) => handleSwitchToSavedKey('primary', savedId)}
          onFetchModels={() => handleFetchSlotModels('primary')}
          onSaveCurrentToSavedKeys={() => handleSaveSlotToSavedKeys('primary')}
        />

        {/* Fallback AI Engine */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[12px] font-semibold text-[#1A1C21]">
              <WuiIcon type="bolt" size="s" className="text-[#006BB4]" />
              <span>Fallback Engine Otomatis (Fail-Safe jika Primary gagal / timeout / rate-limit)</span>
            </div>
            <label className="flex items-center gap-2 cursor-pointer text-[12px]">
              <input
                type="checkbox"
                checked={aiConfig.fallback_enabled}
                onChange={(e) => updateAi((prev) => ({ ...prev, fallback_enabled: e.target.checked }))}
                className="rounded text-[#006BB4] focus:ring-0"
              />
              <span className="font-medium text-[#1A1C21]">Aktifkan Fallback</span>
            </label>
          </div>

          {aiConfig.fallback_enabled && (
            <ProviderConfigFields
              title="Engine Cadangan (Fallback LLM)"
              subtitle="Otomatis mengambil alih inferensi apabila provider utama mengalami gangguan."
              provider={aiConfig.fallback_provider}
              model={aiConfig.fallback_model}
              apiKey={aiConfig.fallback_api_key}
              hasApiKey={aiConfig.has_fallback_api_key}
              baseUrl={aiConfig.fallback_base_url}
              showKey={showFallbackKey}
              savedKeys={savedKeys}
              selectedSavedKeyId={aiConfig.fallback_saved_key_id}
              availableModels={resolveAvailableModels('fallback')}
              loadingModels={loadingModelsKey === 'fallback'}
              modelsStatus={slotModelsStatus.fallback}
              onToggleShowKey={() => setShowFallbackKey(!showFallbackKey)}
              onProviderChange={(nextProvider, defaultModel) => {
                setSlotModels((prev) => ({ ...prev, fallback: [] }));
                setSlotModelsStatus((prev) => ({ ...prev, fallback: null }));
                updateAi((prev) => ({
                  ...prev,
                  fallback_provider: nextProvider,
                  fallback_model: defaultModel,
                  fallback_saved_key_id: '',
                  clear_fallback_api_key: false,
                }));
              }}
              onModelChange={(nextModel) => updateAi((prev) => ({ ...prev, fallback_model: nextModel }))}
              onApiKeyChange={(nextKey) =>
                updateAi((prev) => ({
                  ...prev,
                  fallback_api_key: nextKey,
                  fallback_saved_key_id: '',
                  clear_fallback_api_key: false,
                }))
              }
              onClearApiKey={() =>
                updateAi((prev) => ({
                  ...prev,
                  fallback_api_key: '',
                  has_fallback_api_key: false,
                  fallback_saved_key_id: '',
                  clear_fallback_api_key: true,
                }))
              }
              onBaseUrlChange={(nextUrl) => updateAi((prev) => ({ ...prev, fallback_base_url: nextUrl }))}
              onSelectSavedKey={(savedId) => handleSwitchToSavedKey('fallback', savedId)}
              onFetchModels={() => handleFetchSlotModels('fallback')}
              onSaveCurrentToSavedKeys={() => handleSaveSlotToSavedKeys('fallback')}
            />
          )}
        </div>

        {/* Saved API Keys & Available Models Manager */}
        <div className="p-4 bg-[#FAFBFD] border border-[#E1E6EB] rounded space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-[13px] font-semibold text-[#1A1C21] flex items-center gap-1.5">
                <WuiIcon type="lock" size="s" className="text-[#006BB4]" />
                <span>Saved API Keys ({savedKeys.length})</span>
              </div>
              <div className="text-[11px] text-[#5A626F]">
                Simpan beberapa API key beserta daftar model yang tersedia di masing-masing key untuk switch cepat ke Primary atau Fallback.
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowAddSavedKey(!showAddSavedKey)}
              className="h-7 px-2.5 bg-white hover:bg-[#F5F7FA] text-[#006BB4] border border-[#D3DAE6] rounded-[4px] text-[11px] font-medium flex items-center gap-1 cursor-pointer"
            >
              <WuiIcon type={showAddSavedKey ? 'cross' : 'plus'} size="xs" />
              <span>{showAddSavedKey ? 'Tutup Form' : 'Tambah API Key'}</span>
            </button>
          </div>

          {savedKeysFeedback && <WuiCallOut tone={savedKeysFeedback.tone}>{savedKeysFeedback.text}</WuiCallOut>}

          {showAddSavedKey && (
            <div className="p-3 bg-white border border-[#D3DAE6] rounded-[4px] space-y-3 text-[12px]">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                <div>
                  <label className="block text-[#1A1C21] font-medium mb-1">Nama Profil</label>
                  <input
                    type="text"
                    value={newSavedKey.name}
                    onChange={(e) => setNewSavedKey({ ...newSavedKey, name: e.target.value })}
                    placeholder="Experiential Labs Free"
                    className="w-full px-2.5 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4]"
                  />
                </div>
                <div>
                  <label className="block text-[#1A1C21] font-medium mb-1">Provider Platform</label>
                  <select
                    value={newSavedKey.provider}
                    onChange={(e) => {
                      const nextMeta = getProviderMeta(e.target.value);
                      setNewSavedKey({
                        ...newSavedKey,
                        provider: e.target.value,
                        model: nextMeta.defaultModel,
                        models: [],
                      });
                      setNewSavedModelsStatus(null);
                    }}
                    className="w-full px-2.5 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] bg-white"
                  >
                    {AI_PROVIDERS.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-[#1A1C21] font-medium mb-1">API Key</label>
                  <div className="relative">
                    <input
                      type={showNewSavedKey ? 'text' : 'password'}
                      value={newSavedKey.api_key}
                      onChange={(e) => setNewSavedKey({ ...newSavedKey, api_key: e.target.value })}
                      placeholder={getProviderMeta(newSavedKey.provider).keyLabel}
                      className="w-full pl-2.5 pr-8 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px]"
                    />
                    <button
                      type="button"
                      onClick={() => setShowNewSavedKey(!showNewSavedKey)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-[#8A94A6] hover:text-[#1A1C21]"
                    >
                      {showNewSavedKey ? <WuiIcon type="eyeClosed" size="s" /> : <WuiIcon type="eye" size="s" />}
                    </button>
                  </div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-[#1A1C21] font-medium">Model Default</label>
                    <button
                      type="button"
                      disabled={loadingModelsKey === 'new_saved'}
                      onClick={async () => {
                        const res = await fetchModelsFromServer({
                          keyTag: 'new_saved',
                          provider: newSavedKey.provider,
                          api_key: newSavedKey.api_key,
                          base_url: newSavedKey.base_url,
                        });
                        setNewSavedModelsStatus(res.statusText);
                        if (res.ok) {
                          const firstChat = res.models.find((m) => m.chat_supported !== false);
                          setNewSavedKey((prev) => ({
                            ...prev,
                            models: res.models,
                            model: prev.model || firstChat?.id || '',
                          }));
                        }
                      }}
                      className="text-[11px] text-[#006BB4] hover:underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
                    >
                      <WuiIcon type="refresh" size="xs" className={loadingModelsKey === 'new_saved' ? 'animate-spin' : ''} />
                      <span>Cek Model</span>
                    </button>
                  </div>
                  <div className="flex gap-1.5">
                    <input
                      type="text"
                      value={newSavedKey.model}
                      onChange={(e) => setNewSavedKey({ ...newSavedKey, model: e.target.value })}
                      className="w-full px-2.5 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px]"
                    />
                    {newSavedKey.models.length > 0 && (
                      <select
                        value=""
                        onChange={(e) => {
                          if (e.target.value) setNewSavedKey({ ...newSavedKey, model: e.target.value });
                        }}
                        className="px-2 py-1.5 border border-[#D3DAE6] rounded text-[11px] bg-white max-w-[140px]"
                      >
                        <option value="" disabled>
                          Pilih ({newSavedKey.models.length})
                        </option>
                        {newSavedKey.models.map((m) => (
                          <option key={m.id} value={m.id} disabled={m.chat_supported === false}>
                            {m.label || m.id}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                  {newSavedModelsStatus && (
                    <div className="text-[11px] text-[#535966] mt-1 font-mono">{newSavedModelsStatus}</div>
                  )}
                </div>
              </div>
              {getProviderMeta(newSavedKey.provider).supportsBaseUrl && (
                <div>
                  <label className="block text-[#1A1C21] font-medium mb-1">Base URL Endpoint (Opsional)</label>
                  <input
                    type="text"
                    value={newSavedKey.base_url}
                    onChange={(e) => setNewSavedKey({ ...newSavedKey, base_url: e.target.value })}
                    placeholder={getProviderMeta(newSavedKey.provider).baseUrlPlaceholder}
                    className="w-full px-2.5 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] font-mono text-[12px]"
                  />
                </div>
              )}
              <div className="flex justify-end">
                <button
                  type="button"
                  disabled={savingSavedKeys}
                  onClick={handleAddNewSavedKey}
                  className="h-7 px-3 bg-[#006BB4] hover:bg-[#00538C] text-white rounded-[4px] text-[11px] font-medium cursor-pointer disabled:opacity-50"
                >
                  {savingSavedKeys ? 'Menyimpan...' : 'Simpan ke Daftar'}
                </button>
              </div>
            </div>
          )}

          {savedKeys.length === 0 ? (
            <div className="text-[12px] text-[#69707D] py-2">
              Belum ada Saved API Key. Klik &quot;Tambah API Key&quot; atau &quot;Simpan ke Saved Keys&quot; pada panel Primary/Fallback di atas.
            </div>
          ) : (
            <div className="overflow-x-auto border border-[#E1E6EB] rounded-[4px] bg-white">
              <table className="w-full text-left border-collapse text-[12px]">
                <thead>
                  <tr className="border-b border-[#E1E6EB] bg-[#FAFBFD] text-[#535966] text-[11px]">
                    <th className="py-2 px-3 font-semibold">Profil</th>
                    <th className="py-2 px-3 font-semibold">Provider</th>
                    <th className="py-2 px-3 font-semibold">API Key</th>
                    <th className="py-2 px-3 font-semibold">Model Aktif &amp; Daftar Model Key</th>
                    <th className="py-2 px-3 font-semibold text-right">Switch / Aksi</th>
                  </tr>
                </thead>
                <tbody>
                  {savedKeys.map((sk) => {
                    const isPrimaryActive = aiConfig.primary_saved_key_id === sk.id;
                    const isFallbackActive = aiConfig.fallback_saved_key_id === sk.id;
                    const models = sk.models || [];
                    const freeCount = models.filter((m) => m.free).length;
                    const loadingThis = loadingModelsKey === `saved:${sk.id}`;
                    const testThis = savedKeyTests[sk.id];
                    const testingThis = Boolean(testThis?.loading);
                    const testResp = (testThis?.response || '').trim();
                    const isOkReply = /\bok\b/i.test(testResp);
                    return (
                      <tr key={sk.id} className="border-b border-[#F0F2F5] last:border-b-0">
                        <td className="py-2 px-3 font-medium text-[#1A1C21]">
                          <div>{sk.name}</div>
                          {(isPrimaryActive || isFallbackActive) && (
                            <div className="text-[10px] font-mono text-[#017D73] mt-0.5">
                              {isPrimaryActive && isFallbackActive
                                ? 'AKTIF: PRIMARY + FALLBACK'
                                : isPrimaryActive
                                  ? 'AKTIF: PRIMARY'
                                  : 'AKTIF: FALLBACK'}
                            </div>
                          )}
                        </td>
                        <td className="py-2 px-3 text-[#535966]">{getProviderMeta(sk.provider).shortLabel}</td>
                        <td className="py-2 px-3 font-mono text-[11px] text-[#535966]">
                          {sk.api_key_masked || (sk.api_key && !sk.api_key.includes('•') ? `${sk.api_key.slice(0, 4)}••••••••${sk.api_key.slice(-4)}` : sk.api_key) || '-'}
                        </td>
                        <td className="py-2 px-3">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="font-mono text-[11px] text-[#1A1C21]">{sk.model || '-'}</span>
                            {models.length > 0 && (
                              <select
                                value={sk.model || ''}
                                disabled={savingSavedKeys}
                                onChange={(e) => handleUpdateSavedKeyModel(sk, e.target.value)}
                                aria-label={`Pilih model untuk ${sk.name}`}
                                className="h-6 px-1.5 border border-[#D3DAE6] rounded-[4px] text-[11px] bg-white font-mono max-w-[230px]"
                              >
                                {!models.some((m) => m.id === sk.model) && sk.model && (
                                  <option value={sk.model}>{sk.model}</option>
                                )}
                                {models.map((m) => (
                                  <option key={m.id} value={m.id} disabled={m.chat_supported === false}>
                                    {m.label || m.id}
                                  </option>
                                ))}
                              </select>
                            )}
                          </div>
                          <div className="text-[10px] text-[#69707D] font-mono mt-0.5">
                            {models.length > 0
                              ? freeCount > 0
                                ? `${models.length} model (${freeCount} free)`
                                : `${models.length} model`
                              : 'Belum dimuat'}
                          </div>
                          {testThis && !testThis.loading && (
                            <div
                              className={`text-[10.5px] font-mono mt-1 whitespace-pre-wrap break-words max-w-[520px] ${
                                testThis.success ? 'text-[#017D73]' : 'text-[#BD271E]'
                              }`}
                            >
                              {testThis.success
                                ? `Test ${isOkReply ? 'OK' : 'Sukses'}${typeof testThis.latency_ms === 'number' ? ` (${testThis.latency_ms}ms)` : ''}: ${testResp}`
                                : `Test Gagal: ${testThis.error || 'Unknown error'}`}
                            </div>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right">
                          <div className="inline-flex items-center justify-end gap-1">
                            <button
                              type="button"
                              onClick={() => handleSwitchToSavedKey('primary', sk.id)}
                              title={isPrimaryActive ? 'Aktif sebagai Primary' : 'Pakai sebagai Primary'}
                              aria-label={`Pakai ${sk.name} sebagai Primary`}
                              className={`w-7 h-7 inline-flex items-center justify-center border rounded-[4px] transition-colors cursor-pointer ${
                                isPrimaryActive
                                  ? 'border-[#006BB4] bg-[#EBF5FB] text-[#006BB4]'
                                  : 'border-[#D3DAE6] bg-white hover:bg-[#F5F7FA] text-[#006BB4]'
                              }`}
                            >
                              <WuiIcon type="bolt" size="s" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleSwitchToSavedKey('fallback', sk.id)}
                              title={isFallbackActive ? 'Aktif sebagai Fallback' : 'Pakai sebagai Fallback'}
                              aria-label={`Pakai ${sk.name} sebagai Fallback`}
                              className={`w-7 h-7 inline-flex items-center justify-center border rounded-[4px] transition-colors cursor-pointer ${
                                isFallbackActive
                                  ? 'border-[#017D73] bg-[#E6F4F3] text-[#017D73]'
                                  : 'border-[#D3DAE6] bg-white hover:bg-[#F5F7FA] text-[#535966]'
                              }`}
                            >
                              <WuiIcon type="pulse" size="s" />
                            </button>
                            <button
                              type="button"
                              disabled={testingThis}
                              onClick={() => handleTestSavedKey(sk)}
                              title="Test model (cek apakah mengembalikan OK)"
                              aria-label={`Test model ${sk.name}`}
                              className="w-7 h-7 inline-flex items-center justify-center border border-[#D3DAE6] rounded-[4px] bg-white hover:bg-[#F5F7FA] text-[#017D73] transition-colors cursor-pointer disabled:opacity-50"
                            >
                              <WuiIcon
                                type={testingThis ? 'refresh' : 'play'}
                                size="s"
                                className={testingThis ? 'animate-spin' : ''}
                              />
                            </button>
                            <button
                              type="button"
                              disabled={loadingThis}
                              onClick={() => handleFetchSavedKeyModels(sk)}
                              title="Muat daftar model"
                              aria-label={`Muat daftar model ${sk.name}`}
                              className="w-7 h-7 inline-flex items-center justify-center border border-[#D3DAE6] rounded-[4px] bg-white hover:bg-[#F5F7FA] text-[#535966] transition-colors cursor-pointer disabled:opacity-50"
                            >
                              <WuiIcon type="refresh" size="s" className={loadingThis ? 'animate-spin' : ''} />
                            </button>
                            <button
                              type="button"
                              disabled={savingSavedKeys}
                              onClick={() => handleDeleteSavedKey(sk)}
                              title="Hapus Saved API Key"
                              aria-label={`Hapus ${sk.name}`}
                              className="w-7 h-7 inline-flex items-center justify-center border border-[#D3DAE6] rounded-[4px] bg-white hover:bg-[#FDECEB] text-[#BD271E] transition-colors cursor-pointer disabled:opacity-50"
                            >
                              <WuiIcon type="trash" size="s" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
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
              onChange={(e) => updateAi((prev) => ({ ...prev, temperature: parseFloat(e.target.value) }))}
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
              onChange={(e) => updateAi((prev) => ({ ...prev, max_tokens: parseInt(e.target.value, 10) || 1500 }))}
              className="w-full px-3 py-1.5 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] text-[12px]"
            />
          </div>
        </div>

        <div>
          <label className="block text-[#1A1C21] font-medium mb-1">System Instruction / Prompt Guidance</label>
          <textarea
            rows={2}
            value={aiConfig.system_instruction}
            onChange={(e) => updateAi((prev) => ({ ...prev, system_instruction: e.target.value }))}
            className="w-full px-3 py-2 border border-[#D3DAE6] rounded outline-none focus:border-[#006BB4] text-[12px] font-sans"
            placeholder="Petunjuk gaya bahasa analisis AI untuk triage notifikasi..."
          />
        </div>

        {/* Live Test AI Inference Playground */}
        <div className="p-3.5 bg-[#FAFBFD] border border-[#D3DAE6] rounded-[4px] space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12px] font-semibold text-[#1A1C21] flex items-center gap-1.5">
              <WuiIcon type="machineLearningApp" size="s" className="ouiIcon--mono text-[#006BB4]" />
              <span>Live AI Inference Benchmark (Uji Primary, Fallback &amp; Failover)</span>
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => handleRunAiTest('primary')}
                disabled={isTestingAi}
                className="px-2.5 py-1 bg-[#006BB4] hover:bg-[#00538C] text-white rounded-[4px] text-[11px] font-medium flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                {isTestingAi ? <WuiIcon type="refresh" size="xs" className="animate-spin" /> : <WuiIcon type="play" size="xs" />}
                <span>Uji Primary</span>
              </button>
              {aiConfig.fallback_enabled && (
                <>
                  <button
                    type="button"
                    onClick={() => handleRunAiTest('fallback')}
                    disabled={isTestingAi}
                    className="px-2.5 py-1 bg-white hover:bg-[#F5F7FA] text-[#1A1C21] border border-[#D3DAE6] rounded-[4px] text-[11px] font-medium flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                  >
                    <WuiIcon type="play" size="xs" className="text-[#006BB4]" />
                    <span>Uji Fallback</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleRunAiTest('auto')}
                    disabled={isTestingAi}
                    className="px-2.5 py-1 bg-white hover:bg-[#F5F7FA] text-[#1A1C21] border border-[#D3DAE6] rounded-[4px] text-[11px] font-medium flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                  >
                    <WuiIcon type="bolt" size="xs" className="text-[#017D73]" />
                    <span>Uji Auto-Fallback</span>
                  </button>
                </>
              )}
            </div>
          </div>
          <input
            type="text"
            value={testPrompt}
            onChange={(e) => setTestPrompt(e.target.value)}
            className="w-full h-8 px-3 bg-white border border-[#D3DAE6] rounded-[4px] text-[12px] outline-none focus:border-[#006BB4]"
            placeholder="Masukkan prompt uji analisis..."
          />

          {testResult && (
            <WuiCallOut
              tone={testResult.success ? 'success' : 'danger'}
              title={
                testResult.success
                  ? `Sukses (${getProviderMeta(testResult.provider).shortLabel}: ${testResult.model || aiConfig.model}${testResult.used_fallback ? ' [via Fallback]' : ''})${testResult.latency_ms !== undefined ? ` - ${testResult.latency_ms} ms` : ''}`
                  : 'Gagal Inferensi'
              }
            >
              {testResult.primary_error && (
                <div className="text-[11px] text-[#8A5300] mb-1">
                  Catatan Primary gagal: {testResult.primary_error}
                </div>
              )}
              <p className="whitespace-pre-wrap">{testResult.response || testResult.error}</p>
            </WuiCallOut>
          )}
        </div>
      </WuiPanel>

      {/* SECTION 2: Multi-Source Threat Intelligence Synthesis */}
      <WuiPanel
        title="Multi-Source Threat Intelligence Synthesis (Ensemble)"
        subtitle="Sintesis koroborasi multi-intelijen: VirusTotal, MalwareBazaar, AlienVault OTX, dan MISP OSINT."
        accentColor="#007871"
        right={
          <div className="flex items-center gap-2 text-[12px]">
            <span className="text-[#535966] font-medium">Mode Konsensus:</span>
            <select
              value={tiConfig.consensus_mode}
              onChange={(e) => setTiConfig({ ...tiConfig, consensus_mode: e.target.value })}
              className="h-8 px-2.5 border border-[#D3DAE6] rounded-[4px] text-[12px] font-semibold bg-white focus:outline-none focus:border-[#006BB4]"
            >
              <option value="ensemble">Ensemble (Zero False-Negative)</option>
              <option value="majority">Majority Vote (Minimal 2 Sumber)</option>
              <option value="vt_first">Primary VT with Fallback</option>
            </select>
          </div>
        }
        bodyClassName="p-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Card VirusTotal */}
          <div className="p-4 border border-[#D3DAE6] rounded-[4px] bg-[#FAFBFD] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <WuiIcon type="globe" size="m" className="text-[#006BB4]" />
                <span className="font-semibold text-[#1A1C21] text-[13px]">1. VirusTotal API (Reputasi Hash Global)</span>
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
                className="rounded-[2px] text-[#006BB4] focus:ring-0"
              />
            </div>
            <div className="grid grid-cols-2 gap-2 text-[12px]">
              <div>
                <label className="block text-[#535966] mb-1">Ambang Deteksi HIGH</label>
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
                  className="w-full h-8 px-2.5 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px]"
                />
                <span className="text-[10px] text-[#69707D]">Minimal engine terdeteksi</span>
              </div>
              <div>
                <label className="block text-[#535966] mb-1">Ambang CRITICAL</label>
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
                  className="w-full h-8 px-2.5 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px]"
                />
                <span className="text-[10px] text-[#69707D]">Auto-quarantine</span>
              </div>
            </div>
            <div>
              <label className="block text-[#535966] text-[12px] mb-1">API Key VirusTotal</label>
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
                  className="w-full h-8 pl-2.5 pr-8 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px] font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowVtKey(!showVtKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#69707D]"
                >
                  {showVtKey ? <WuiIcon type="eyeClosed" size="s" /> : <WuiIcon type="eye" size="s" />}
                </button>
              </div>
            </div>
          </div>

          {/* Card MalwareBazaar */}
          <div className="p-4 border border-[#D3DAE6] rounded-[4px] bg-[#FAFBFD] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <WuiIcon type="database" size="m" className="text-[#006BB4]" />
                <span className="font-semibold text-[#1A1C21] text-[13px]">2. MalwareBazaar (Signature Database)</span>
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
                className="rounded-[2px] text-[#006BB4] focus:ring-0"
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
                  className="rounded-[2px] text-[#006BB4] focus:ring-0"
                />
                <span className="text-[#1A1C21]">Eskalasi Otomatis ke HIGH jika signature terdaftar</span>
              </label>
              <p className="text-[11px] text-[#69707D]">
                Mencegah celah false-negative ketika hash sampel baru belum terindeks penuh di engine antivirus VT.
              </p>
            </div>
            <div>
              <label className="block text-[#535966] text-[12px] mb-1">API Key MalwareBazaar (Auth-Key)</label>
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
                  className="w-full h-8 pl-2.5 pr-8 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px] font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowMbKey(!showMbKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#69707D]"
                >
                  {showMbKey ? <WuiIcon type="eyeClosed" size="s" /> : <WuiIcon type="eye" size="s" />}
                </button>
              </div>
            </div>
          </div>

          {/* Card AlienVault OTX */}
          <div className="p-4 border border-[#D3DAE6] rounded-[4px] bg-[#FAFBFD] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <WuiIcon type="memory" size="m" className="text-[#006BB4]" />
                <span className="font-semibold text-[#1A1C21] text-[13px]">3. AlienVault OTX (Open Threat Exchange)</span>
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
                className="rounded-[2px] text-[#006BB4] focus:ring-0"
              />
            </div>
            <div className="text-[12px]">
              <label className="block text-[#535966] mb-1">Ambang Batas Pulses (Threat Pulses)</label>
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
                className="w-full h-8 px-2.5 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px]"
              />
              <span className="text-[10px] text-[#69707D]">Minimal pulse untuk mengindikasikan file berbahaya</span>
            </div>
            <div>
              <label className="block text-[#535966] text-[12px] mb-1">API Key OTX</label>
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
                  className="w-full h-8 pl-2.5 pr-8 border border-[#D3DAE6] rounded-[4px] bg-white text-[12px] font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowOtxKey(!showOtxKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#69707D]"
                >
                  {showOtxKey ? <WuiIcon type="eyeClosed" size="s" /> : <WuiIcon type="eye" size="s" />}
                </button>
              </div>
            </div>
          </div>

          {/* Card MISP OSINT & Cache TTL */}
          <div className="p-4 border border-[#D3DAE6] rounded-[4px] bg-[#FAFBFD] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <WuiIcon type="database" size="m" className="text-[#006BB4]" />
                <span className="font-semibold text-[#1A1C21] text-[13px]">4. MISP OSINT &amp; Cache TTL Policy</span>
              </div>
              <label className="inline-flex items-center gap-1.5 text-[11px] text-[#535966] cursor-pointer">
                <span>MISP Feed</span>
                <input
                  type="checkbox"
                  checked={tiConfig.sources.misp.enabled}
                  onChange={(e) => {
                    setTiConfig({
                      ...tiConfig,
                      sources: {
                        ...tiConfig.sources,
                        misp: { ...tiConfig.sources.misp, enabled: e.target.checked },
                      },
                    });
                    setHasUnsavedChanges(true);
                  }}
                  className="rounded-[2px] text-[#006BB4] focus:ring-0"
                />
              </label>
            </div>
            <div className="grid grid-cols-3 gap-2 text-[12px]">
              <div>
                <label className="block text-[#535966] mb-1">TTL Malicious</label>
                <input
                  type="number"
                  min="1"
                  max="30"
                  value={tiConfig.cache_ttl.malicious_days}
                  onChange={(e) => {
                    setTiConfig({
                      ...tiConfig,
                      cache_ttl: { ...tiConfig.cache_ttl, malicious_days: parseInt(e.target.value, 10) || 7 },
                    });
                    setHasUnsavedChanges(true);
                  }}
                  className="w-full h-8 px-2 border border-[#D3DAE6] rounded-[4px] bg-white text-[11px]"
                />
                <span className="text-[10px] text-[#69707D]">Hari</span>
              </div>
              <div>
                <label className="block text-[#535966] mb-1">TTL Clean</label>
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
                  className="w-full h-8 px-2 border border-[#D3DAE6] rounded-[4px] bg-white text-[11px]"
                />
                <span className="text-[10px] text-[#69707D]">Jam</span>
              </div>
              <div>
                <label className="block text-[#535966] mb-1">TTL Unknown</label>
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
                  className="w-full h-8 px-2 border border-[#D3DAE6] rounded-[4px] bg-white text-[11px]"
                />
                <span className="text-[10px] text-[#69707D]">Jam</span>
              </div>
            </div>
            <p className="text-[11px] text-[#69707D] pt-1 leading-relaxed">
              Diferensial TTL melindungi kuota gratis API eksternal (maksimal 4 request/menit pada VT) saat armada 100 endpoint mengalami lonjakan insiden serentak.
            </p>
          </div>
        </div>
      </WuiPanel>
    </form>
  );
}
