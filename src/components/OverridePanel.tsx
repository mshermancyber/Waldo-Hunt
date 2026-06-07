import type { OverrideMap } from '../types';
import { AWS_LOGS, ONPREM_LOGS, DEFAULT_ST } from '../data/logSources';

interface OverridePanelProps {
  env: 'aws' | 'onprem' | 'both' | null;
  awsRecKeys: string[];
  opRecKeys: string[];
  overrides: OverrideMap;
  onOverride: (key: string, field: 'index' | 'sourcetype', value: string) => void;
}

export function OverridePanel({ env, awsRecKeys, opRecKeys, overrides, onOverride }: OverridePanelProps) {
  const showAws = env === 'aws' || env === 'both';
  const showOnprem = env === 'onprem' || env === 'both';

  const sources: { key: string; label: string; defIdx: string; defSt: string }[] = [];
  if (showAws) {
    awsRecKeys.forEach((k) => {
      const src = AWS_LOGS[k];
      if (src) sources.push({ key: k, label: src.label, defIdx: src.index, defSt: DEFAULT_ST[k] || '' });
    });
  }
  if (showOnprem) {
    opRecKeys.forEach((k) => {
      const src = ONPREM_LOGS[k];
      if (src) sources.push({ key: k, label: src.label, defIdx: src.index, defSt: DEFAULT_ST[k] || '' });
    });
  }

  if (!sources.length) {
    return (
      <div className="override-panel">
        <div className="override-panel-hd">⚙ Index / Sourcetype Overrides</div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
          Select log sources to configure overrides.
        </div>
      </div>
    );
  }

  return (
    <div className="override-panel">
      <div className="override-panel-hd">⚙ Index / Sourcetype Overrides</div>
      <div className="override-grid">
        {sources.map((s) => (
          <div className="override-field" key={s.key}>
            <div className="override-label">{s.label}</div>
            <input
              className="override-input"
              type="text"
              maxLength={128}
              placeholder={`index=${s.defIdx}`}
              value={overrides[s.key]?.index || ''}
              onChange={(e) => onOverride(s.key, 'index', e.target.value)}
            />
            <input
              className="override-input"
              type="text"
              maxLength={256}
              placeholder={`sourcetype=${s.defSt}`}
              value={overrides[s.key]?.sourcetype || ''}
              onChange={(e) => onOverride(s.key, 'sourcetype', e.target.value)}
              style={{ marginTop: '4px' }}
            />
          </div>
        ))}
      </div>
      <div className="override-note">
        Leave blank to use defaults. Changes update SPL output in real-time.
      </div>
    </div>
  );
}
