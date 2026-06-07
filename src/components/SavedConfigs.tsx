import { useState, useEffect } from 'react';
import type { Environment, Pattern, OverrideMap } from '../types';

interface SavedConfig {
  id: string;
  name: string;
  timestamp: string;
  env: Environment;
  patterns: Pattern[];
  activities: string[];
  awsLogs: string[];
  onpremLogs: string[];
  overrides: OverrideMap;
}

const STORAGE_KEY = 'waldohunt-configs';

interface SavedConfigsProps {
  env: Environment;
  patterns: Pattern[];
  activities: string[];
  awsLogs: string[];
  onpremLogs: string[];
  overrides: OverrideMap;
  onLoad: (config: SavedConfig) => void;
}

const VALID_PATTERNS = ['sabotage', 'ip_theft', 'fraud', 'espionage', 'data_manip', 'third_party', 'disclosure', 'workplace'];
const VALID_ENVS = ['aws', 'onprem', 'both'];

function isValidConfig(c: unknown): c is SavedConfig {
  if (!c || typeof c !== 'object') return false;
  const cfg = c as Record<string, unknown>;
  return (
    typeof cfg.id === 'string' && cfg.id.length > 0 &&
    typeof cfg.name === 'string' &&
    typeof cfg.timestamp === 'string' &&
    (cfg.env === null || (typeof cfg.env === 'string' && VALID_ENVS.includes(cfg.env))) &&
    Array.isArray(cfg.patterns) && (cfg.patterns as unknown[]).every((p: unknown) => p === null || (typeof p === 'string' && VALID_PATTERNS.includes(p))) &&
    Array.isArray(cfg.activities) && (cfg.activities as unknown[]).every((a: unknown) => typeof a === 'string') &&
    Array.isArray(cfg.awsLogs) && (cfg.awsLogs as unknown[]).every((l: unknown) => typeof l === 'string') &&
    Array.isArray(cfg.onpremLogs) && (cfg.onpremLogs as unknown[]).every((l: unknown) => typeof l === 'string') &&
    typeof cfg.overrides === 'object' && cfg.overrides !== null
  );
}

function loadConfigs(): SavedConfig[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return [];
    const parsed: unknown = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isValidConfig).slice(0, 20);
  } catch {
    return [];
  }
}

export function SavedConfigs({ env, patterns, activities, awsLogs, onpremLogs, overrides, onLoad }: SavedConfigsProps) {
  const [configs, setConfigs] = useState<SavedConfig[]>(() => loadConfigs());
  const [name, setName] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(configs));
  }, [configs]);

  const handleSave = () => {
    if (!name.trim()) return;
    const config: SavedConfig = {
      id: Date.now().toString(36),
      name: name.trim(),
      timestamp: new Date().toISOString(),
      env,
      patterns,
      activities,
      awsLogs,
      onpremLogs,
      overrides,
    };
    setConfigs((prev) => [config, ...prev].slice(0, 20)); // keep max 20
    setName('');
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleDelete = (id: string) => {
    setConfigs((prev) => prev.filter((c) => c.id !== id));
  };

  const patternLabel = (p: Pattern): string => {
    const labels: Record<string, string> = {
      sabotage: 'IT Sabotage',
      ip_theft: 'IP Theft',
      fraud: 'Fraud',
      espionage: 'Espionage',
    };
    return p ? labels[p] || p : '';
  };

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">💾 Saved Configurations</div>

      {/* Save row */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
        <input
          className="override-input"
          type="text"
          placeholder="Configuration name (e.g., 'AWS Prod - IP Theft')"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{ flex: 1 }}
          onKeyDown={(e) => { if (e.key === 'Enter') handleSave(); }}
        />
        <button
          className="btn btn-primary"
          onClick={handleSave}
          disabled={!name.trim()}
          style={{ fontSize: '9px', padding: '6px 14px' }}
        >
          {saved ? 'Saved!' : 'Save'}
        </button>
      </div>

      {/* Saved configs list */}
      {configs.length === 0 ? (
        <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
          No saved configurations yet. Build a detection setup and save it for quick recall.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '300px', overflowY: 'auto' }}>
          {configs.map((c) => (
            <div
              key={c.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '8px 12px',
                background: 'var(--bg)',
                border: '1px solid var(--border)',
              }}
            >
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-bright)' }}>
                  {c.name}
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', marginTop: '2px' }}>
                  {c.env?.toUpperCase()} · {c.patterns.map(patternLabel).join(', ')} · {c.activities.length} activities · {new Date(c.timestamp).toLocaleDateString()}
                </div>
              </div>
              <button
                className="copy-btn"
                onClick={() => onLoad(c)}
                style={{ fontSize: '8px' }}
              >
                Load
              </button>
              <button
                className="copy-btn"
                onClick={() => handleDelete(c.id)}
                style={{ fontSize: '8px', borderColor: 'var(--red)' }}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
