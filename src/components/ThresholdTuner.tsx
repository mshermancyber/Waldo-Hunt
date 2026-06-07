import { useState, useEffect } from 'react';

interface ThresholdDef {
  key: string;
  label: string;
  defaultValue: number;
  min: number;
  max: number;
  step: number;
  unit: string;
}

const THRESHOLD_DEFS: Record<string, ThresholdDef[]> = {
  delete_data: [
    { key: 'delete_count', label: 'Delete Count Threshold', defaultValue: 100, min: 10, max: 10000, step: 10, unit: 'objects' },
  ],
  resource_destroy: [
    { key: 'destroy_count', label: 'Destroy Count Threshold', defaultValue: 5, min: 1, max: 100, step: 1, unit: 'resources' },
    { key: 'unique_action_types', label: 'Unique Action Types', defaultValue: 2, min: 1, max: 20, step: 1, unit: 'types' },
  ],
  s3_exfil: [
    { key: 'download_count', label: 'Download Count Threshold', defaultValue: 200, min: 10, max: 100000, step: 10, unit: 'objects' },
    { key: 'total_gb', label: 'Total GB Threshold', defaultValue: 10, min: 0.1, max: 1000, step: 0.5, unit: 'GB' },
  ],
  priv_escalation: [
    { key: 'action_count', label: 'Action Count Threshold', defaultValue: 2, min: 1, max: 50, step: 1, unit: 'actions' },
  ],
  recon: [
    { key: 'api_count', label: 'API Count Threshold', defaultValue: 50, min: 10, max: 10000, step: 10, unit: 'calls' },
    { key: 'unique_apis', label: 'Unique APIs Threshold', defaultValue: 5, min: 2, max: 50, step: 1, unit: 'apis' },
  ],
  lateral_move: [
    { key: 'unique_systems', label: 'Unique Systems', defaultValue: 3, min: 1, max: 50, step: 1, unit: 'systems' },
    { key: 'logon_count', label: 'Logon Count', defaultValue: 10, min: 5, max: 1000, step: 5, unit: 'logons' },
  ],
  c2_comms: [
    { key: 'unique_dests', label: 'Unique Destinations', defaultValue: 50, min: 5, max: 500, step: 5, unit: 'destinations' },
    { key: 'conn_count', label: 'Connection Count', defaultValue: 100, min: 10, max: 10000, step: 10, unit: 'connections' },
  ],
  usb_exfil: [
    { key: 'file_count', label: 'File Count Threshold', defaultValue: 20, min: 5, max: 1000, step: 5, unit: 'files' },
  ],
  credential_harvest: [
    { key: 'cred_ops', label: 'Credential Operations', defaultValue: 5, min: 1, max: 100, step: 1, unit: 'operations' },
  ],
  persistence: [
    { key: 'mechanism_count', label: 'Mechanism Count', defaultValue: 2, min: 1, max: 10, step: 1, unit: 'mechanisms' },
  ],
};

interface ThresholdTunerProps {
  activity: string;
  onThresholdsChange: (thresholds: Record<string, number>) => void;
}

export function ThresholdTuner({ activity, onThresholdsChange }: ThresholdTunerProps) {
  const defs = THRESHOLD_DEFS[activity] || [];
  const [values, setValues] = useState<Record<string, number>>(() => {
    const init: Record<string, number> = {};
    defs.forEach((d) => { init[d.key] = d.defaultValue; });
    return init;
  });

  useEffect(() => {
    onThresholdsChange(values);
  }, [values, onThresholdsChange]);

  if (!defs.length) return null;

  return (
    <div className="override-panel" style={{ marginTop: '12px', marginBottom: '20px' }}>
      <div className="override-panel-hd">🎚 Detection Threshold Tuner — {activity}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {defs.map((def) => (
          <div key={def.key} style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <label style={{
                fontFamily: 'var(--mono)',
                fontSize: '9px',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: 'var(--text-mid)',
              }}>
                {def.label}
              </label>
              <span style={{
                fontFamily: 'var(--mono)',
                fontSize: '13px',
                color: 'var(--green)',
                fontWeight: 600,
              }}>
                {values[def.key]} {def.unit}
              </span>
            </div>
            <input
              type="range"
              min={def.min}
              max={def.max}
              step={def.step}
              value={values[def.key]}
              onChange={(e) => setValues((v) => ({ ...v, [def.key]: parseFloat(e.target.value) }))}
              style={{
                width: '100%',
                accentColor: 'var(--green)',
                background: 'var(--bg)',
              }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)' }}>
              <span>{def.min} {def.unit}</span>
              <span>{def.max} {def.unit}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
