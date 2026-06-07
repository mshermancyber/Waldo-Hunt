import { useState } from 'react';
import { AWS_LOGS, ONPREM_LOGS } from '../data/logSources';

interface VolumeEstimatorProps {
  selectedAwsLogs: string[];
  selectedOnpremLogs: string[];
  env: 'aws' | 'onprem' | 'both' | null;
}

// Approximate daily data volumes per log source in GB/day
const VOLUME_ESTIMATES: Record<string, { small: number; medium: number; large: number }> = {
  cloudtrail:  { small: 0.5, medium: 3, large: 20 },
  s3access:    { small: 1, medium: 10, large: 50 },
  vpcflow:     { small: 2, medium: 15, large: 100 },
  guardduty:   { small: 0.1, medium: 0.5, large: 2 },
  iam:         { small: 0.1, medium: 0.5, large: 1 },
  config:      { small: 0.1, medium: 0.3, large: 1 },
  cloudwatch:  { small: 0.5, medium: 5, large: 30 },
  macie:       { small: 0.05, medium: 0.2, large: 1 },
  securityhub: { small: 0.05, medium: 0.2, large: 0.5 },
  codecommit:  { small: 0.01, medium: 0.1, large: 0.5 },
  ad:          { small: 0.5, medium: 3, large: 15 },
  winsec:      { small: 1, medium: 10, large: 50 },
  dlp:         { small: 0.5, medium: 5, large: 20 },
  edr:         { small: 2, medium: 15, large: 80 },
  proxy:       { small: 1, medium: 10, large: 50 },
  siem_alerts: { small: 0.1, medium: 0.5, large: 2 },
};

type EnvSize = 'small' | 'medium' | 'large';

export function VolumeEstimator({ selectedAwsLogs, selectedOnpremLogs, env }: VolumeEstimatorProps) {
  const [envSize, setEnvSize] = useState<EnvSize>('medium');

  const calculateGB = (keys: string[]): number => {
    return keys.reduce((sum, k) => {
      const est = VOLUME_ESTIMATES[k];
      return est ? sum + est[envSize] : sum;
    }, 0);
  };

  const awsGB = calculateGB(selectedAwsLogs);
  const onpremGB = calculateGB(selectedOnpremLogs);
  const totalGB = awsGB + onpremGB;
  const dailySVC = Math.ceil(totalGB * 1.15 / 100) * 100; // Splunk Virtual Compute units, rough estimate

  return (
    <div className="override-panel" style={{ marginTop: '12px' }}>
      <div className="override-panel-hd">📊 Data Volume Estimator</div>

      <div style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
        {(['small', 'medium', 'large'] as EnvSize[]).map((size) => (
          <button
            key={size}
            className={`log-toggle ${envSize === size ? 'selected' : ''}`}
            onClick={() => setEnvSize(size)}
          >
            <span className="dot" />
            {size === 'small' ? 'Small (< 100 nodes)' : size === 'medium' ? 'Medium (100-500 nodes)' : 'Large (500+ nodes)'}
          </button>
        ))}
      </div>

      {env && env !== 'both' ? (
        <div style={{ display: 'flex', gap: '24px' }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-mid)', marginBottom: '4px' }}>
              Estimated Daily Volume
            </div>
            <div style={{ fontFamily: 'var(--cond)', fontSize: '28px', fontWeight: 700, color: 'var(--green)' }}>
              {totalGB.toFixed(1)} GB
            </div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-mid)', marginBottom: '4px' }}>
              Approx. Splunk SVC
            </div>
            <div style={{ fontFamily: 'var(--cond)', fontSize: '28px', fontWeight: 700, color: 'var(--amber)' }}>
              {dailySVC} SVC
            </div>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', gap: '24px' }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-mid)', marginBottom: '4px' }}>
              AWS ({selectedAwsLogs.length} sources)
            </div>
            <div style={{ fontFamily: 'var(--cond)', fontSize: '22px', fontWeight: 700, color: 'var(--amber)' }}>
              {awsGB.toFixed(1)} GB/day
            </div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-mid)', marginBottom: '4px' }}>
              On-Prem ({selectedOnpremLogs.length} sources)
            </div>
            <div style={{ fontFamily: 'var(--cond)', fontSize: '22px', fontWeight: 700, color: 'var(--blue)' }}>
              {onpremGB.toFixed(1)} GB/day
            </div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-mid)', marginBottom: '4px' }}>
              Combined Total
            </div>
            <div style={{ fontFamily: 'var(--cond)', fontSize: '22px', fontWeight: 700, color: 'var(--green)' }}>
              {totalGB.toFixed(1)} GB/day
            </div>
          </div>
        </div>
      )}

      <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginTop: '10px', lineHeight: 1.6 }}>
        ⚠ Estimates assume {envSize} environment. Actual volume depends on event rates, log verbosity, and retention settings.
        Splunk SVC estimate = daily GB × 1.15 overhead ÷ 100, rounded up. Use for sizing guidance only.
      </div>
    </div>
  );
}
