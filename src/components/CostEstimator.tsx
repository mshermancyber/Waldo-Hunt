import { useState } from 'react';
import { estimateCost, estimateBatchCost, optimizeRetention } from '../data/costEstimator';
import type { CostEstimate, RetentionConfig } from '../data/costEstimator';

interface CostEstimatorProps {
  activities: string[];
}

type EnvSize = 'small' | 'medium' | 'large';

export function CostEstimator({ activities }: CostEstimatorProps) {
  const [envSize, setEnvSize] = useState<EnvSize>('medium');
  const [showRetention, setShowRetention] = useState(false);

  const batch = estimateBatchCost(activities, envSize);
  const perDetection = activities.map(a => ({
    activity: a,
    estimate: estimateCost(a, envSize),
    retention: optimizeRetention(a, envSize, 90, 30),
  }));

  // Find biggest cost driver
  const sorted = [...perDetection].sort((a, b) => b.estimate.annualLicenseCost - a.estimate.annualLicenseCost);
  const topThree = sorted.slice(0, 3);

  const formatCurrency = (n: number): string => {
    if (n >= 1000000) return `$${(n / 1000000).toFixed(1)}M`;
    if (n >= 1000) return `$${(n / 1000).toFixed(0)}K`;
    return `$${n}`;
  };

  return (
    <div>
      {/* Environment size selector */}
      <div className="override-panel" style={{ marginTop: '12px' }}>
        <div className="override-panel-hd">💰 Splunk License Cost Estimator</div>

        <div style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
          {(['small', 'medium', 'large'] as EnvSize[]).map(size => (
            <button key={size}
              className={`log-toggle ${envSize === size ? 'selected' : ''}`}
              onClick={() => setEnvSize(size)}>
              <span className="dot" />
              {size === 'small' ? 'Small (<100 nodes)' : size === 'medium' ? 'Medium (100-500)' : 'Large (500+)'}
            </button>
          ))}
        </div>

        {/* Total cost cards */}
        <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '16px' }}>
          <CostCard label="Total GB/Day" value={`${batch.totalGbDay} GB`} color="var(--blue)" />
          <CostCard label="Splunk SVC" value={`${batch.totalSVC}`} color="var(--amber)" />
          <CostCard label="Annual License" value={formatCurrency(batch.totalLicense)} color="var(--red)" />
          <CostCard label="Total Annual Cost" value={formatCurrency(batch.totalAnnual)} color="var(--text-bright)" />
        </div>

        {/* ROI */}
        <div style={{ padding: '12px 14px', background: 'rgba(34,197,94,0.06)', border: '1px solid var(--green-dim)', marginBottom: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)', marginBottom: '2px' }}>
                Cost-Benefit Analysis (avg insider incident = $500K)
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)' }}>
                Total annual detection cost vs. incident cost avoided
              </div>
            </div>
            <div style={{ fontFamily: 'var(--cond)', fontSize: '24px', fontWeight: 700, color: 'var(--green)' }}>
              {formatCurrency(batch.totalAnnual)} → {formatCurrency(500000)} avoided
            </div>
          </div>
        </div>

        {/* Per-detection table */}
        <table className="mitre-table" style={{ marginBottom: 0 }}>
          <thead>
            <tr>
              <th>Detection</th>
              <th>GB/Day</th>
              <th>License/Year</th>
              <th>Triage (hrs/mo)</th>
              <th>Total/Year</th>
              <th>ROI</th>
              <th>Payback</th>
            </tr>
          </thead>
          <tbody>
            {perDetection.map(({ activity, estimate, retention }) => (
              <tr key={activity}
                style={{ background: topThree.some(t => t.activity === activity) ? 'rgba(239,68,68,0.04)' : 'transparent' }}>
                <td className="mitre-technique" style={{ fontSize: '10px' }}>
                  {topThree.some(t => t.activity === activity) ? '🔴 ' : ''}
                  {activity.replace(/_/g, ' ')}
                </td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--blue)' }}>{estimate.gbPerDay}</td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--red)' }}>{formatCurrency(estimate.annualLicenseCost)}</td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-mid)' }}>{estimate.triageHoursPerMonth}h</td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-bright)', fontWeight: 600 }}>{formatCurrency(estimate.totalAnnualCost)}</td>
                <td>
                  <span style={{
                    fontFamily: 'var(--mono)', fontSize: '9px', padding: '2px 6px',
                    color: estimate.roiMultiplier >= 100 ? 'var(--green)' : estimate.roiMultiplier >= 10 ? 'var(--amber)' : 'var(--red)',
                    fontWeight: 600,
                  }}>
                    {estimate.roiMultiplier}x
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)' }}>{estimate.paybackPeriod}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {topThree.some(t => t.estimate.annualLicenseCost > 5000) && (
          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--amber)', marginTop: '10px', lineHeight: 1.6 }}>
            ⚠ Top cost drivers (🔴): {topThree.map(t => t.activity.replace(/_/g, ' ')).join(', ')}. Consider data filtering or sampling for high-volume sources.
          </div>
        )}
      </div>

      {/* Retention Optimizer */}
      <div className="override-panel" style={{ marginTop: '12px' }}>
        <div className="override-panel-hd">📦 Data Retention Optimizer</div>

        <button className="log-toggle" onClick={() => setShowRetention(!showRetention)} style={{ marginBottom: showRetention ? '10px' : '0' }}>
          <span className="dot" />{showRetention ? 'Hide' : 'Show'} Retention Analysis
        </button>

        {showRetention && (
          <table className="mitre-table" style={{ marginBottom: 0 }}>
            <thead>
              <tr>
                <th>Detection</th>
                <th>Daily GB</th>
                <th>Current Retention</th>
                <th>Required</th>
                <th>Savings if Reduced</th>
                <th>Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {perDetection.map(({ activity, retention }) => (
                <tr key={activity}>
                  <td className="mitre-technique" style={{ fontSize: '10px' }}>{activity.replace(/_/g, ' ')}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--blue)' }}>{retention.currentDailyGB} GB</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-mid)' }}>{retention.currentRetentionDays}d</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--green)' }}>{retention.requiredRetentionDays}d</td>
                  <td>
                    {retention.currentRetentionDays > retention.requiredRetentionDays ? (
                      <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--green)', fontWeight: 600 }}>
                        {formatCurrency(retention.savingsIfReducedAnnual)}/yr
                      </span>
                    ) : (
                      <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-dim)' }}>—</span>
                    )}
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '8px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                    {retention.recommendation}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function CostCard({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{ flex: 1, minWidth: '130px', padding: '10px 14px', background: 'var(--s1)', border: '1px solid var(--border)', textAlign: 'center' }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '7px', letterSpacing: '0.1em', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: '4px' }}>{label}</div>
      <div style={{ fontFamily: 'var(--cond)', fontSize: '22px', fontWeight: 700, color }}>{value}</div>
    </div>
  );
}
